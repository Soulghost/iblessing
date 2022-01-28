import Foundation
import XPCSupport

class ServiceDelegate: NSObject {
}

extension ServiceDelegate: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: XPCStringManipulationService.self)
        let exportedObject = StringManipulation()
        newConnection.exportedObject = exportedObject
        newConnection.resume()
        
        return true
    }
}
