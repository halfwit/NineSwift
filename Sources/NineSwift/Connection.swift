//
//  Connection.swift
//  Altid - Connect with a service over 9p
//
//  Created by halfwit on 2024-01-03.
//

import Foundation
import Network

@available(macOS 10.15, *)
func applicationServiceParameters() -> NWParameters {
    let tcpOptions = NWProtocolTCP.Options()
    tcpOptions.enableKeepalive = true
    tcpOptions.keepaliveIdle = 2
    tcpOptions.keepaliveCount = 2
    tcpOptions.keepaliveInterval = 2
    tcpOptions.noDelay = true
    
    let params: NWParameters = NWParameters(tls: nil, tcp: tcpOptions)
    params.includePeerToPeer = true

    let nineOptions = NWProtocolFramer.Options(definition: NineProtocol.definition)
    params.defaultProtocolStack.applicationProtocols.insert(nineOptions, at: 0)
    
    return params
}

@available(macOS 10.15, *)
var sharedConnection: PeerConnection?

@available(macOS 10.15, *)
let wcb = NWConnection.SendCompletion.contentProcessed { cbe in
    if cbe != nil {
        print("Callback error encountered: \(String(describing: cbe))")
    }
}

@available(macOS 10.15, *)
protocol PeerConnectionDelegate: AnyObject {
    func connectionReady()
    func connectionFailed()
    func displayAdvertiseError(_ error: NWError)
}

@available(macOS 10.15, *)
class PeerConnection {
    weak var delegate: PeerConnectionDelegate?
    var connection: NWConnection?
    let name: String
    let initiatedConnection: Bool
    var sendQueue = Queue<Enqueued>()
    var handles: [Handle] = [Handle]()
    var running: Bool = false
    
    /* Connect to a service */
    @available(macOS 10.15, *)
    init(name: String, delegate: PeerConnectionDelegate) {
        self.delegate = delegate
        self.name = name
        self.initiatedConnection = true
        
        guard let endpointPort = NWEndpoint.Port("12345") else { return }
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host("localhost"), port: endpointPort)
        //let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host("127.0.0.1"), port: endpointPort)
        //let endpoint = NWEndpoint.service(name: name, type: "_altid._tcp.", domain: "local.", interface: nil)
        connection = NWConnection(to: endpoint, using: applicationServiceParameters())
    }
    
    func addHandle(handle: Handle) {
        handles.append(handle)
    }
    
    func cancel() {
        if let connection = self.connection {
            connection.cancel()
            self.connection = nil
        }
    }
    
    // Handle starting the peer-to-peer connection for both inbound and outbound connections.
    @available(macOS 10.15, *)
    func startConnection() {
        guard let connection = self.connection else {
            return
        }
        
        connection.stateUpdateHandler = { [weak self] newState in
            switch newState {
            case .ready:
            
                if let delegate = self?.delegate {
                    delegate.connectionReady()
                }
            case .failed(let error):
                print("\(connection) failed with \(error)")
                connection.cancel()
                if let initiated = self?.initiatedConnection,
                   initiated && error == NWError.posix(.ECONNABORTED) {
                    // Reconnect if the user suspends the app on the nearby device.
                    guard let endpointPort = NWEndpoint.Port("12345") else { return }
                    let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host("192.168.0.248"), port: endpointPort)
                    //let endpoint = NWEndpoint.service(name: self!.name, type: "_altid._tcp", domain: "local", interface: nil)
                    let connection = NWConnection(to: endpoint, using: applicationServiceParameters())
                    self?.connection = connection
                    self?.startConnection()
                } else if let delegate = self?.delegate {
                    delegate.connectionFailed()
                }
            default:
                break
            }
        }
        
        connection.start(queue: .main)
    }
}

/* Utility functions */
@available(macOS 10.15, *)
extension PeerConnection {
    func connect(uname: String = "") {
        send(Tversion())
        send(Tattach(fid: 0, afid: 0, uname: uname, aname: ""))
    }
    
    func run() {
        if sendQueue.size > 0 {
            _runjob()
        }
    }
    
    func flush(_ handle: Handle) {
        let tag = UInt16(handles.count > 1 ? handles.count : 1)
        send(Tflush(tag: tag, oldtag: handle.tag))
    }
    
    func stat(_ handle: Handle, callback: @escaping (nineStat) -> Void) {
        send(Tstat(tag: handle.tag, fid: handle.fid)) { (stat: nineStat) in
            callback(stat)
        }
    }
    
    func close(_ handle: Handle) {
        if let index = self.handles.firstIndex(where: { $0.fid == handle.fid }) {
            self.handles.remove(at: index)
        }
        send(Tclunk(tag: handle.tag, fid: handle.fid))
    }
    
    func open(_ wname: String, mode: nineMode, callback: @escaping (Handle) -> Void) {
        var handle = Handle(fid: 1, tag: 0, name: wname)
    Again:
        for h in handles {
            /* Walk it off the end of the chain, or pop it in a hole */
            if h.fid == handle.fid {
                handle.fid += 1
                continue Again
            }
            if h.tag == handle.tag {
                handle.tag += 1
                continue Again
            }
        }
        self.addHandle(handle: handle)
        /* Be careful that we do not continue if we error here */
        self.send(Twalk(fid: 0, newFid: handle.fid, wname: wname)) { (error: NineErrors) in
            if(error == NineErrors.success) {
                self.send(Topen(tag: handle.tag, fid: handle.fid, mode: mode)) { (msg: NWProtocolFramer.Message) in
                    /* iounit occassionally is misparsed in 9p */
                    handle.iounit = msg.iounit > 0 ? msg.iounit : 8168
                    callback(handle)
                }
            } else {
                self.close(handle)
            }
        }
    }
    
    func read(_ handle: Handle, offset: UInt64 = 0, count: UInt32 = 8168, callback: @escaping (String) -> Void) {
        send(Tread(tag: handle.tag, fid: handle.fid, offset: offset, count: count)) { (data: String) in
            callback(data)
        }
    }
    
    func write(_ handle: Handle, data: Data, offset: UInt64 = 0, callback: @escaping (NineErrors) -> Void) {
        send(Twrite(tag: handle.tag, fid: handle.fid, offset: offset, count: UInt32(data.count), bytes: data)) { (error: NineErrors) in
            callback(error)
        }
    }
    
    private func send(_ message: QueueableMessage) {
        _enqueue(message) { (msg, content, error) in }
    }
    
    private func send(_ message: QueueableMessage, callback: @escaping (NWProtocolFramer.Message) -> Void) {
        _enqueue(message) { (msg, content, error) in
            callback(msg)
        }
    }
    
    private func send(_ message: QueueableMessage, callback: @escaping (String) -> Void) {
        _enqueue(message) { (msg, content, error) in
            guard let content = content else {
                return
            }
            callback(String(decoding:content, as: UTF8.self))
        }
    }
    
    private func send(_ message: QueueableMessage, callback: @escaping (NineErrors) -> Void) {
        _enqueue(message) { (msg, content, error ) in
            switch error {
            case .none:
                callback(.success)
            case .some(_):
                callback(.decodeError)
            }
        }
    }
    
    private func send(_ message: QueueableMessage, callback: @escaping (nineStat) -> Void) {
        _enqueue(message) { (msg, content, error ) in
            if let stat = msg.stat {
                callback(stat)
            }
        }
    }
    
    private func _enqueue( _ message: QueueableMessage, callback: @escaping (NWProtocolFramer.Message, Data?, NWError?) -> Void) {
        sendQueue.enqueue(Enqueued(message: message, action: callback))
    }
    
    func _runjob() {
        guard let item = sendQueue.dequeue() else { return }
        guard let connection = self.connection else { return }
        connection.batch {
            connection.send(content: item.message.encodedData, contentContext: item.message.context, isComplete: true, completion: .idempotent)
            connection.receiveMessage { (content, context, isComplete, error) in
                if let msg = context?.protocolMetadata(definition: NineProtocol.definition) as? NWProtocolFramer.Message {
                    if(msg.type == nineType.Rerror) {
                        print("Error encountered: \(String(decoding: content!, as: UTF8.self))")
                    } else {
                        item.action(msg, content, error)
                    }
                    self._runjob()
                }
            }
        }
    }
}
