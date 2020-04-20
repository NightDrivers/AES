//
//  AESTests.m
//  AESTests
//
//  Created by ldc on 2020/4/20.
//  Copyright © 2020 Xiamen Hanin. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "AES.h"

@interface AESTests : XCTestCase

@property (nonatomic, strong) AES *aes;

@end

@implementation AESTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
    self.aes = [[AES alloc] init];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testECBMode {
    
    [self.aes configureOptions:AESOptionsPKCS7Padding | AESOptionsECBMode key:@"12345678901234567890123456789012" vi:nil];
    NSString *origin;
    NSData *originData;
    BOOL flag;
    
    origin = @"afacjkli3yc8q49393rc43wewgcwtrjtdsvg";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"pzmJONAFX1Ao7DWFYj7d0AJ6Lsncorw7ZfASp2E0LXnpk08dd64jdudX5PUl8COV"];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj123456789";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"hbEtzRbeKA9NCi3zQLh9PUGYq0CBSHwhOhyCvEBK18g="];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj12345678";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"RWvm7sEkQDDM2oCM3xPeow=="];
    XCTAssertTrue(flag);
    
    self.aes.options = AESOptionsECBMode;
    origin = @"afacjkli3yc8q49393rc43wewgcwtrjtdsvg";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"pzmJONAFX1Ao7DWFYj7d0AJ6Lsncorw7ZfASp2E0LXlN4kQ03XI3IJETOgoyJAER"];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj123456789";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"hbEtzRbeKA9NCi3zQLh9PXuUZ55SZL+EBpxoZDMH74A="];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj12345678";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"hKhsH1wcIBkLx609Uwzswg=="];
    XCTAssertTrue(flag);
}

- (void)testCBCMode {
    
    [self.aes configureOptions:AESOptionsPKCS7Padding key:@"123456789012345678901234" vi:@"1234567890123456"];
    NSString *origin;
    NSData *originData;
    BOOL flag;
    
    origin = @"afacjkli3yc8q49393rc43wewgcwtrjtdsvg";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"CAwn5104VcotF8EWzAr0Rk48Rm+wiApfwiF/l4DZJEs0c1l7+tS0gVbOnKmFUZOs"];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj123456789";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"Hj2S5zpuX+Fx6T5hgZ9E1mcTqnCf4nOQk8TcMNsfneE="];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj12345678";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"JrRgjzxJyLL/ELfF0xCLhA=="];
    XCTAssertTrue(flag);
    
    self.aes.options = 0;
    origin = @"afacjkli3yc8q49393rc43wewgcwtrjtdsvg";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"CAwn5104VcotF8EWzAr0Rk48Rm+wiApfwiF/l4DZJEvK0scan+BQNP6UyAu4LfE0"];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj123456789";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"Hj2S5zpuX+Fx6T5hgZ9E1kFBaTV2PIns+LOYYvKlFO4="];
    XCTAssertTrue(flag);
    
    origin = @"asdfghj12345678";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"24oaGBdl9yVzVj6+3yX7EA=="];
    XCTAssertTrue(flag);
}

- (void)test128bitKey {
    
    [self.aes configureOptions:AESOptionsPKCS7Padding | AESOptionsECBMode key:@"1234567890123456" vi:nil];
    NSString *origin;
    NSData *originData;
    BOOL flag;
    
    origin = @"abcdefghijklmnopqrst";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"/K1xW9c7XLBIj4QPO614ibf8CRvG2jouJvwS+1gYZCo="];
    XCTAssertTrue(flag);
    
    origin = @"12345678901234567890123456789012";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"dXzNDNxckOrb7uz2ON0AAMa/oq6BhXPyhbLV8HHxnGcFAYegzeWphyy6sJGrc+VT"];
    XCTAssertTrue(flag);
    
    origin = @"1234567890123456789012345678901";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"dXzNDNxckOrb7uz2ON0AAHBeWlyKxa2sfLltaLuvS3Y="];
    XCTAssertTrue(flag);
    
    self.aes.options = AESOptionsECBMode;
    origin = @"abcdefghijklmnopqrst";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"/K1xW9c7XLBIj4QPO614iSh02mzgi7Q+F7BjrHDeook="];
    XCTAssertTrue(flag);
    
    origin = @"12345678901234567890123456789012";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"dXzNDNxckOrb7uz2ON0AAMa/oq6BhXPyhbLV8HHxnGfYtZhIx2cMlLKbVNI3ni56"];
    XCTAssertTrue(flag);
    
    origin = @"1234567890123456789012345678901";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"dXzNDNxckOrb7uz2ON0AABcb+De/052FjNtU4c4WzHo="];
    XCTAssertTrue(flag);
    
    [self.aes configureOptions:AESOptionsPKCS7Padding key:@"1234567890123456" vi:@"asdfghj123456789"];
    origin = @"abcdefghijklmnopqrst";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"Sd7D4JYqkbj201vFu/9DRVt6cZAHG7yeJrqtXAVesbc="];
    XCTAssertTrue(flag);
    
    origin = @"12345678901234567890123456789012";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"e3VFoXn8M70TrbYgA6e+hnabggr4PyXHWbX259B80jP9Z5RCyMf963HttawkabGa"];
    XCTAssertTrue(flag);
    
    origin = @"1234567890123456789012345678901";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"e3VFoXn8M70TrbYgA6e+hvXAcdi2UIhIrAqmRhJj6XI="];
    XCTAssertTrue(flag);
    
    self.aes.options = 0;
    origin = @"abcdefghijklmnopqrst";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"Sd7D4JYqkbj201vFu/9DRSNV7PVd1SFtbeY4Uhlq0xw="];
    XCTAssertTrue(flag);
    
    origin = @"12345678901234567890123456789012";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"e3VFoXn8M70TrbYgA6e+hnabggr4PyXHWbX259B80jNNQHDUf9bzHMYUdnQt/uXU"];
    XCTAssertTrue(flag);
    
    origin = @"1234567890123456789012345678901";
    originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    flag = [[[self.aes encrypt:originData] base64EncodedStringWithOptions:0] isEqualToString:@"e3VFoXn8M70TrbYgA6e+hj4G2YfS8sno4neS0w1fask="];
    XCTAssertTrue(flag);
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
