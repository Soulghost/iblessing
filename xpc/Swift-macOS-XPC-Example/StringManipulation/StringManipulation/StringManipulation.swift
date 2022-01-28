import Foundation
import XPCSupport

public class StringManipulation: NSObject {
}

extension StringManipulation: XPCStringManipulationService {
    public func uppercase(_ string: String, with reply: (String) -> Void) {
        reply(string.uppercased())
    }
    
    public func lowercase(_ string: String, with reply: (String) -> Void) {
        reply(string.lowercased())
    }
    
    public func capitalize(_ string: String, with reply: (String) -> Void) {
        reply(string.capitalized)
    }
}
