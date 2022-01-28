import Cocoa
import XPCSupport

class ViewController: NSViewController {

    let xpcConnection = NSXPCConnection(serviceName: XPCStringManipulationServiceName)
    var xpcErrorHandler: ((Error) -> Void)?
    var stringManipulator: XPCStringManipulationService?
    
    @IBOutlet var textView: NSTextView!
    
    deinit {
        xpcConnection.invalidate()
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        xpcConnection.remoteObjectInterface = NSXPCInterface(with: XPCStringManipulationService.self)
        xpcConnection.resume()
        
        xpcConnection.interruptionHandler = {
            // Handle interruption
        }

        xpcConnection.invalidationHandler = {
            // Handle invalidation
        }

        xpcErrorHandler = { error in
            let alert = NSAlert(error: error)
            DispatchQueue.main.async {
                alert.runModal()
            }
        }
        
        guard
            let errorHandler = xpcErrorHandler,
            let xpcService = xpcConnection.remoteObjectProxyWithErrorHandler(errorHandler) as? XPCStringManipulationService
            else {
                assertionFailure("Unable to set up XPC connection to \(xpcConnection)")
                return
        }
        
        stringManipulator = xpcService
    }
    
    @IBAction func uppercase(_ sender: Any?) {
        stringManipulator?.uppercase(textView.string) { [weak self] (reply) in
            DispatchQueue.main.async {
                self?.textView.string = reply
            }
        }
    }

    @IBAction func lowercase(_ sender: Any?) {
        stringManipulator?.lowercase(textView.string, with:  { (reply) in
            DispatchQueue.main.async {
                self.textView.string = reply
            }
        })
    }

    @IBAction func capitalize(_ sender: Any?) {
        stringManipulator?.capitalize(textView.string) { [weak self] (reply) in
            DispatchQueue.main.async {
                self?.textView.string = reply
            }
        }
    }
}
