import Foundation
import UXSPSdk

public class UXSPSdkTests {
    public static void runAllTests() {
        let field1 = "UXSP-1".data(using: .utf8)!
        let field2 = "swift".data(using: .utf8)!
        let bound = UXSPClient.bindFields([field1, field2])
        assert(bound.count == (4 + field1.count + 4 + field2.count), "Bind fields length error")
        print("Swift SDK Tests passed")
    }
}
