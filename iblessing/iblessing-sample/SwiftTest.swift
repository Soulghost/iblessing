//
//  SwiftTest.swift
//  iblessing-sample
//
//  Created by soulghost on 2021/10/30.
//  Copyright © 2021 soulghost. All rights reserved.
//

import Foundation
import UIKit

class StaticSwiftClass {
    public var version: String
    
    init() {
        version = "2.33"
    }
    
    func pboardContent() -> String {
        let content = UIPasteboard.general.string!
        return content + version
    }
    
    func sysVer() -> String {
        return UIDevice.current.systemVersion;
    }
}

@objc class SwiftObjcEntry : NSObject {
    @objc func main() -> String {
        let s = StaticSwiftClass()
        s.version = s.sysVer()
        return s.pboardContent()
    }
}
