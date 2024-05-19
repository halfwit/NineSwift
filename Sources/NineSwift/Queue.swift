//
//  Queue.swift
//  Altid
//
//  Created by halfwit on 2024-01-22.
//
import Foundation
import Network

struct Queue<T> {
    private var elements: [T] = []
    
    mutating func enqueue(_ value: T) {
        elements.append(value)
    }
    
    mutating func dequeue() -> T? {
        guard !elements.isEmpty else {
            return nil
        }
        return elements.removeFirst()
    }
    
    var size: Int {
        get {
            return elements.count
        }
    }
}

@available(macOS 10.15, *)
protocol QueueableMessage {
    var encodedData: Data {get}
    var minReceiveLength: Int {get}
    var context: NWConnection.ContentContext {get}
}

@available(macOS 10.15, *)
struct Enqueued {
    let message: QueueableMessage
    let action: (NWProtocolFramer.Message, Data?, NWError?) -> Void
    init(message: QueueableMessage, action: @escaping (NWProtocolFramer.Message, Data?, NWError?) -> Void) {
        self.message = message
        self.action = action
    }
}
