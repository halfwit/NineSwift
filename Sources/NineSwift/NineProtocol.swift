//
//  NineProtocol.swift
//  Altid - 9p implementation
//
//  Created by halfwit on 2024-01-03.
//

import Foundation
import Network

var MSIZE: UInt32 = 8192
let version = "9P2000 ".data(using: .utf8)!

enum NineErrors: Error {
    case decodeError
    case unknownType
    case connectError
    case success
}

enum nineType: UInt8 {
    case Tversion = 100
    case Tauth = 102
    case Tattach = 104
    case Tflush = 108
    case Twalk = 110
    case Topen = 112
    case Tcreate = 114
    case Tread = 116
    case Twrite = 118
    case Tclunk = 120
    case Tremove = 122
    case Tstat = 124
    case Twstat = 126
    case Rversion = 101
    case Rauth = 103
    case Rattach = 105
    case Rerror = 107
    case Rflush = 109
    case Rwalk = 111
    case Ropen = 113
    case Rcreate = 115
    case Rread = 117
    case Rwrite = 119
    case Rclunk = 121
    case Rremove = 123
    case Rstat = 125
    case Rwstat = 127
    case invalid = 0
}

enum fileType: UInt8, Codable {
    case dir = 128
    case append = 64
    case excl = 32
    case invalid = 16
    case auth = 8
    case tmp = 4
    case file = 0
}

enum nineMode: UInt8, Codable {
    case read = 0
    case write = 1
    case rdwr = 2
    case exec = 3
    case trunc = 0x10
    case rclose = 0x40
}

struct nineQid: Codable {
    var type: fileType
    var version: UInt32
    var path: UInt64
}

struct nineStat: Codable {
    var size: UInt16
    var type: UInt16
    var dev: UInt32
    var qid: nineQid
    var mode: UInt32
    var atime: UInt32
    var mtime: UInt32
    var length: UInt64
    var name: Data
    var uid: Data
    var gid: Data
    var muid: Data
}

// Main framing protocol
@available(macOS 10.15, *)
class NineProtocol: NWProtocolFramerImplementation {
    static let definition = NWProtocolFramer.Definition(implementation: NineProtocol.self)
    static var label: String { return "9p" }
    
    required init(framer: NWProtocolFramer.Instance) {}
    func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult { return .ready }
    func wakeup(framer: NWProtocolFramer.Instance) { print("In wakeup")}
    func stop(framer: NWProtocolFramer.Instance) -> Bool { print("In stop"); return true }
    func cleanup(framer: NWProtocolFramer.Instance) { print("In cleanup")}
    
    func handleOutput(framer: NWProtocolFramer.Instance, message: NWProtocolFramer.Message, messageLength: Int, isComplete: Bool) {
        do {
            try framer.writeOutputNoCopy(length: messageLength)
        } catch {
            print("Heck didn't send")
        }
    }
    
    func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        let headerSize = 7
        var count: UInt32 = 0
        var type: UInt8 = 0
        var tag: UInt16 = 0
        var dataSize: Int = 0

        let parsed = framer.parseInput(minimumIncompleteLength: headerSize, maximumLength: headerSize) { (buffer, isComplete) -> Int in
            guard let buffer = buffer else {
                return 0
            }
            if buffer.isEmpty {
                return 0
            }
            var offset = 0
            count = r32(buffer: buffer, &offset)
            type = r8(buffer: buffer, &offset)
            tag = r16(buffer: buffer, &offset)
            return offset
        }
        guard parsed else {
            return count > 0 ? Int(count) : headerSize
        }
        let message = NWProtocolFramer.Message(count: count, type: type, tag: tag)
        while true {
            switch type {
            case nineType.Rversion.rawValue:
                let parsed = framer.parseInput(minimumIncompleteLength: 6, maximumLength: 6) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    let msize = r32(buffer: buffer, &offset)
                    MSIZE = (msize != MSIZE) ? msize : MSIZE
                    dataSize = Int(r16(buffer: buffer, &offset))
                    return offset
                }
                guard parsed else {
                    return 6
                }
            case nineType.Rauth.rawValue:
                // Not implemented
                break
            case nineType.Rattach.rawValue:
                let parsed = framer.parseInput(minimumIncompleteLength: 13, maximumLength: 13) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    let qid = rqid(buffer: buffer, &offset)
                    message.qids = [qid]
                    return offset
                }
                guard parsed else {
                    return 13
                }
            case nineType.Rerror.rawValue:
                let parsed = framer.parseInput(minimumIncompleteLength: 2, maximumLength: 2) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    dataSize = Int(r16(buffer: buffer, &offset))
                    return offset
                }
                guard parsed else {
                    return 2
                }
            case nineType.Rflush.rawValue:
                break
            case nineType.Rwalk.rawValue:
                var total = 0
                // 210: qid is 13 bytes. maxpathlen is 16. 2 for nwqid
                let parsed = framer.parseInput(minimumIncompleteLength: 15, maximumLength: 210) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var tmpqids = [nineQid]()
                    var offset = 0
                    let nwqid = r16(buffer: buffer, &offset)
                    total = Int(nwqid > 0 ? nwqid * 13 + 2 : 15)
                    if buffer.count < total {
                        return total
                    }
                    for _ in 1...nwqid {
                        let tmpqid = rqid(buffer: buffer, &offset)
                        tmpqids.append(tmpqid)
                    }
                    message.qids = tmpqids
                    return offset
                }
                guard parsed else {
                    return total
                }
            case nineType.Rcreate.rawValue:
                fallthrough
            case nineType.Ropen.rawValue:
                let parsed = framer.parseInput(minimumIncompleteLength: 17, maximumLength: 17) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    let qid = rqid(buffer: buffer, &offset)
                    message.qids = [qid]
                    message.iounit = r32(buffer: buffer, &offset)
                    return offset
                }
                guard parsed else {
                    return 17
                }
            case nineType.Rread.rawValue:
                let parsed = framer.parseInput(minimumIncompleteLength: 4, maximumLength: 4) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    dataSize = Int(r32(buffer: buffer, &offset))
                    return offset
                }
                guard parsed else {
                    return 4
                }
            case nineType.Rwrite.rawValue:
                // TODO: How much we wrote returned, this is important for our isComplete stuff
                let parsed = framer.parseInput(minimumIncompleteLength: 4, maximumLength: 4) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    _ = r32(buffer: buffer, &offset)
                    return offset
                }
                guard parsed else {
                    return 4
                }
            case nineType.Rclunk.rawValue:
                // 0 bytes back
                break
            case nineType.Rremove.rawValue:
                break
            case nineType.Rstat.rawValue:
                var size: UInt16 = 0
                let parsed = framer.parseInput(minimumIncompleteLength: 36, maximumLength: .max) { (buffer, isComplete) -> Int in
                    guard let buffer = buffer else {
                        return 0
                    }
                    var offset = 0
                    let msize = r16(buffer: buffer, &offset)
                    size = r16(buffer: buffer, &offset)
                    if buffer.count < msize {
                        return 0
                    }
                    let type = r16(buffer: buffer, &offset) // Used by kernel
                    let dev = r32(buffer: buffer, &offset)  // Used by kernel
                    let qid = rqid(buffer: buffer, &offset)
                    let mode = r32(buffer: buffer, &offset)
                    let atime = r32(buffer: buffer, &offset)
                    let mtime = r32(buffer: buffer, &offset)
                    let length = r64(buffer: buffer, &offset)

                    let ncount = r16(buffer: buffer, &offset)
                    let name = rstr(buffer: buffer, count: ncount, &offset)
                    let ucount = r16(buffer: buffer, &offset)
                    let uid = rstr(buffer: buffer, count: ucount, &offset)
                    let gcount = r16(buffer: buffer, &offset)
                    let gid = rstr(buffer: buffer, count: gcount, &offset)
                    let mcount = r16(buffer: buffer, &offset)
                    let muid = rstr(buffer: buffer, count: mcount, &offset)

                    message.stat = nineStat(size: size, type: type, dev: dev, qid: qid, mode: mode, atime: atime, mtime: mtime, length: length, name: name, uid: uid, gid: gid, muid: muid)

                    return offset
                }
                guard parsed else {
                    return Int(size+2)
                }
            case nineType.Rwstat.rawValue:
                break
            default:
                print("Unhandled Rmessage: \(type)")
                return 0
            }
            if !framer.deliverInputNoCopy(length: dataSize, message: message, isComplete: true) {
                return 0
            }
            print(message.count);
            return Int(message.count)
        }
    }
}

@available(macOS 10.15, *)
extension NWProtocolFramer.Message {
    /* Set completions here */
    convenience init(count: UInt32, type: UInt8, tag: UInt16, fid: UInt32 = 0, iounit: UInt32 = 0, qids: [nineQid]? = nil, stat: nineStat? = nil) {
        self.init(definition: NineProtocol.definition)
        self["count"] = count
        self["type"] = type
        self["tag"] = tag
        self["fid"] = fid
        self["iounit"] = iounit
        self["qids"] = qids
        self["stat"] = stat
    }
    
    var count: UInt32 {
        if let val = self["count"] as? UInt32 {
            return val
        }
        return 0
    }
    
    var type: nineType {
        if let val = self["type"] as? UInt8 {
            return nineType(rawValue: val) ?? .invalid
        }
        return .invalid
    }
    
    var tag: UInt16 {
        if let val = self["tag"] as? UInt16 {
            return val
        }
        return 0
    }
    
    var fid: UInt32 {
        if let val = self["fid"] as? UInt32 {
            return val
        }
        return 0
    }
    
    var iounit: UInt32 {
        get {
            if let val = self["fid"] as? UInt32 {
                return val
            }
            return 0
        }
        set {
            self["iounit"] = newValue
        }
    }
    
    var qids: [nineQid]? {
        get {
            if let qids = self["qids"] as? [nineQid] {
                return qids
            }
            return nil
        }
        set {
            self["qids"] = newValue
        }
    }
    var stat: nineStat? {
        get {
            if let stat = self["stat"] as? nineStat {
                return stat
            }
            return nil
        }
        set {
            self["stat"] = newValue
        }
    }
}

@available(macOS 10.15, *)
struct Tversion: QueueableMessage, Encodable {
    var minReceiveLength: Int = 13
    
    var encodedData: Data {
        let count: UInt32 = UInt32(13 + version.count)
        var data = Data(count: 0)
        w32(&data, input: count) // length
        w8(&data, input: nineType.Tversion.rawValue) // type
        w16(&data, input: 0) // tag
        w32(&data, input: MSIZE)
        wstr(&data, input: version)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tversion")
    }
}

@available(macOS 10.15, *)
struct Tauth: QueueableMessage, Encodable {
    var minReceiveLength: Int = 20
    
    let length: UInt32
    let afid: UInt32
    let uname: Data
    let aname: Data
    
    init(afid: UInt32, uname: String, aname: String) {
        
        let size = aname.count+2 + uname.count+2 + 4+1+2+4
        self.length = UInt32(size)
        self.afid = 0xFFFF
        self.uname = uname.data(using: .utf8)!
        self.aname = aname.data(using: .utf8)!
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: length)
        w8(&data, input: nineType.Tauth.rawValue)
        w16(&data, input: 0)
        w32(&data, input: afid)
        wstr(&data, input: uname)
        wstr(&data, input: aname)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tauth")
    }
}

@available(macOS 10.15, *)
struct Tattach: QueueableMessage, Encodable {
    var minReceiveLength: Int = 20
    
    let length: UInt32
    let fid: UInt32
    let afid: UInt32
    let uname: Data
    let aname: Data
    
    init(fid: UInt32, afid: UInt32, uname: String, aname: String) {
        
        let size = aname.count+2 + uname.count+2 + 4+1+2+4+4
        self.length = UInt32(size)
        self.fid = fid
        self.afid = afid /* No auth? Have a global or so to switch */
        self.uname = uname.data(using: .utf8)!
        self.aname = aname.data(using: .utf8)!
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: length)
        w8(&data, input: nineType.Tattach.rawValue)
        w16(&data, input: 0)
        w32(&data, input: 0)
        w32(&data, input: afid)
        wstr(&data, input: uname)
        wstr(&data, input: aname)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tattach")
    }
}

@available(macOS 10.15, *)
struct Tflush: QueueableMessage, Encodable {
    var minReceiveLength: Int = 7
    
    let tag: UInt16
    let oldtag: UInt16
    init(tag: UInt16, oldtag: UInt16) {
        self.tag = 0
        self.oldtag = oldtag
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 11)
        w8(&data, input: nineType.Tflush.rawValue)
        w16(&data, input: tag)
        w16(&data, input: oldtag)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tflush")
    }
}

@available(macOS 10.15, *)
struct Twalk: QueueableMessage, Encodable {
    var minReceiveLength: Int = 22
    
    let length: UInt32
    let tag: UInt16
    let fid: UInt32
    let newFid: UInt32
    let nwnames: UInt16
    let wnames: [Data]
    
    init(fid: UInt32, newFid: UInt32, wname: String) {
        var size = 17
        self.tag = 0
        self.fid = fid
        self.newFid = newFid
        let names = wname.split(separator: "/")
        var tmpwnames = [Data]()
        for name in names {
            tmpwnames.append(name.data(using: .utf8)!)
            size += name.count + 2
        }
        self.length = UInt32(size)
        self.nwnames = UInt16(tmpwnames.count)
        self.wnames = tmpwnames
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: length)
        w8(&data, input: nineType.Twalk.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        w32(&data, input: newFid)
        w16(&data, input: nwnames)
        for wname in wnames {
            wstr(&data, input: wname)
        }
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Twalk")
    }
}

@available(macOS 10.15, *)
struct Topen: QueueableMessage, Encodable {
    var minReceiveLength: Int = 24
    
    let tag: UInt16
    let fid: UInt32
    let mode: nineMode
    
    init(tag: UInt16, fid: UInt32, mode: nineMode) {
        self.tag = tag
        self.fid = fid
        self.mode = mode
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 4+1+2+4+1)
        w8(&data, input: nineType.Topen.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        w8(&data, input: mode.rawValue)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Topen")
    }
}

@available(macOS 10.15, *)
struct Tcreate: QueueableMessage, Encodable {
    var minReceiveLength: Int = 24
    
    let tag: UInt16
    let fid: UInt32
    let name: Data
    let perm: UInt32
    let mode: UInt8
    
    init(tag: UInt16, fid: UInt32, name: String, perm: UInt32, mode: UInt8) {
        self.tag = tag
        self.fid = fid
        self.name = name.data(using: .utf8)!
        self.perm = perm
        self.mode = mode
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: UInt32(name.count + 16))
        w8(&data, input: nineType.Tcreate.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        wstr(&data, input: name)
        w32(&data, input: perm)
        w8(&data, input: mode)
        return data
    }
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tcreate")
    }
}

@available(macOS 10.15, *)
struct Tread: QueueableMessage, Encodable {
    var minReceiveLength: Int = 13
    
    let tag: UInt16
    let fid: UInt32
    let offset: UInt64
    let count: UInt32
    
    init(tag: UInt16, fid: UInt32, offset: UInt64, count: UInt32) {
        self.tag = tag
        self.fid = fid
        self.offset = offset
        self.count = count
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 4+1+2+4+8+4)
        w8(&data, input: nineType.Tread.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        w64(&data, input: offset)
        w32(&data, input: count)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tread")
    }
}

@available(macOS 10.15, *)
struct Twrite: QueueableMessage, Encodable {
    var minReceiveLength: Int = 11
    
    let tag: UInt16
    let fid: UInt32
    let offset: UInt64
    let count: UInt32
    let bytes: Data
    
    init(tag: UInt16, fid: UInt32, offset: UInt64, count: UInt32, bytes: Data) {
        self.tag = tag
        self.fid = fid
        self.offset = offset
        self.count = count
        self.bytes = bytes
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: UInt32(bytes.count + 23))
        w8(&data, input: nineType.Twrite.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        w64(&data, input: offset)
        wdata(&data, input: bytes)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Twrite")
    }
}

@available(macOS 10.15, *)
struct Tclunk: QueueableMessage, Encodable {
    var minReceiveLength: Int = 7
    
    let tag: UInt16
    let fid: UInt32
    init(tag: UInt16, fid: UInt32) {
        self.tag = tag
        self.fid = fid
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 11)
        w8(&data, input: nineType.Tclunk.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tclunk")
    }
}

@available(macOS 10.15, *)
struct Tremove: QueueableMessage, Encodable {
    var minReceiveLength: Int = 7
    
    let tag: UInt16
    let fid: UInt32
    init(tag: UInt16, fid: UInt32) {
        self.tag = tag
        self.fid = fid
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 11)
        w8(&data, input: nineType.Tremove.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tremove")
    }
}

@available(macOS 10.15, *)
struct Tstat: QueueableMessage, Encodable {
    var minReceiveLength: Int = 52
    
    let tag: UInt16
    let fid: UInt32
    init(tag: UInt16, fid: UInt32) {
        self.tag = tag
        self.fid = fid
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        w32(&data, input: 11)
        w8(&data, input: nineType.Tstat.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Tstat")
    }
}

@available(macOS 10.15, *)
struct Twstat: QueueableMessage, Encodable {
    var minReceiveLength: Int = 7
    
    let tag: UInt16
    let fid: UInt32
    let stat: nineStat
    
    init(tag: UInt16, fid: UInt32, stat: nineStat) {
        self.tag = tag
        self.fid = fid
        self.stat = stat
    }
    
    var encodedData: Data {
        var data = Data(count: 0)
        let length = 52 + stat.name.count + stat.uid.count + stat.gid.count + stat.muid.count
        w32(&data, input: UInt32(length))
        w8(&data, input: nineType.Twstat.rawValue)
        w16(&data, input: tag)
        w32(&data, input: fid)
        w16(&data, input: stat.size)
        w16(&data, input: stat.type)
        w32(&data, input: stat.dev)
        w8(&data, input: stat.qid.type.rawValue)
        w32(&data, input: stat.qid.version)
        w64(&data, input: stat.qid.path)
        w32(&data, input: stat.mode)
        w32(&data, input: stat.atime)
        w32(&data, input: stat.mtime)
        w64(&data, input: stat.length)
        wstr(&data, input: stat.name)
        wstr(&data, input: stat.name)
        wstr(&data, input: stat.uid)
        wstr(&data, input: stat.gid)
        wstr(&data, input: stat.muid)
        return data
    }
    
    var context: NWConnection.ContentContext {
        return NWConnection.ContentContext(identifier: "Twstat")
    }
}

/* Utility functions */
func w8(_ data: inout Data, input: UInt8) {
    var tempInput = input.littleEndian
    data.append(Data(bytes: &tempInput, count: MemoryLayout<UInt8>.size))
}

func w16(_ data: inout Data, input: UInt16) {
    w8(&data, input: UInt8(input & 0x00ff))
    w8(&data, input: UInt8(input >> 8))
}

func w32(_ data: inout Data, input: UInt32) {
    w16(&data, input: UInt16(input & 0x0000ffff))
    w16(&data, input: UInt16(input >> 16))
}

func w64(_ data: inout Data, input: UInt64) {
    w32(&data, input: UInt32(input & 0x00000000ffffffff))
    w32(&data, input: UInt32(input >> 32))
}

func wstr(_ data: inout Data, input: Data) {
    let rev = input.reversed()
    w16(&data, input: UInt16(input.count))
    if input.count == 0 {
        return
    }
    // Write out the rest of our bytes
    for i in 0...rev.count - 1 {
        var tempInput = input[i]
        data.append(Data(bytes: &tempInput, count: MemoryLayout<UInt8>.size))
        
    }
}

func wdata(_ data: inout Data, input: Data) {
    let rev = input.reversed()
    // Write out the rest of our bytes
    w32(&data, input: UInt32(input.count))
    if input.count == 0 {
        return
    }
    for i in 0...rev.count - 1 {
        var tempInput = input[i]
        data.append(Data(bytes: &tempInput, count: MemoryLayout<UInt8>.size))
        
    }
}

func r8(buffer: UnsafeMutableRawBufferPointer, _ base: inout Int) -> UInt8 {
    defer {
        base += 1
    }
    return buffer[base]
}

func r16(buffer: UnsafeMutableRawBufferPointer, _ base: inout Int) -> UInt16 {
    defer {
        base += 2
    }
    var bytes = [UInt8]()
    bytes.append(buffer[base])
    bytes.append(buffer[base+1])
    let tempVar = bytes.withUnsafeBytes { $0.load(as: UInt16.self) }
    return tempVar
}

func r32(buffer: UnsafeMutableRawBufferPointer, _ base: inout Int) -> UInt32 {
    defer {
        base += 4
    }
    var bytes = [UInt8]()
    bytes.append(buffer[base])
    bytes.append(buffer[base+1])
    bytes.append(buffer[base+2])
    bytes.append(buffer[base+3])
    let tempVar = bytes.withUnsafeBytes { $0.load(as: UInt32.self) }
    return tempVar
}

/* This is backwards a bit, sooooo */
func r64(buffer: UnsafeMutableRawBufferPointer, _ base: inout Int) -> UInt64 {
    defer {
        base += 8
    }
    var bytes = [UInt8]()
    bytes.append(buffer[base])
    bytes.append(buffer[base+1])
    bytes.append(buffer[base+2])
    bytes.append(buffer[base+3])
    bytes.append(buffer[base+4])
    bytes.append(buffer[base+5])
    bytes.append(buffer[base+6])
    bytes.append(buffer[base+7])
    let tempVar = bytes.withUnsafeBytes { $0.load(as: UInt64.self )}
    return tempVar
}

func rstr(buffer: UnsafeMutableRawBufferPointer, count: UInt16, _ base: inout Int) -> Data {
    var data = Data(count: 0)
    if count < 1 {
        return data
    }
    for _ in 1...count {
        data.append(buffer[base])
        base += MemoryLayout<UInt8>.size
    }
    return data
}

func rdata(buffer: UnsafeMutableRawBufferPointer, count: UInt32, _ base: inout Int) -> Data {
    var data = Data(count: 0)
    if count < 1 {
        return data
    }
    for _ in 1...count {
        data.append(buffer[base])
        base += MemoryLayout<UInt8>.size
    }
    return data
}

func rqid(buffer: UnsafeMutableRawBufferPointer, _ base: inout Int) -> nineQid {
    let type = r8(buffer: buffer, &base)
    let vers = r32(buffer: buffer, &base)
    let path = r64(buffer: buffer, &base)
    return nineQid(type: fileType(rawValue: type) ?? .invalid, version: vers, path: path)
}

extension Data {
    public var bytes: [UInt8]
    {
        return [UInt8](self)
    }
}

extension UInt8 {
    var char: Character {
        return Character(UnicodeScalar(self))
    }
}
