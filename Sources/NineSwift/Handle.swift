//
//  Handle.swift
//  Altid
//
//  Created by halfwit on 2024-01-22.
//

import Foundation

/* Handle to an open nine file */
struct Handle {
    let name: String
    var fid: UInt32
    var iounit: UInt32
    var tag: UInt16
    
    init(fid: UInt32, tag: UInt16, name: String) {
        self.fid = fid
        self.tag = tag
        self.name = name
        self.iounit = 8168
    }
}
