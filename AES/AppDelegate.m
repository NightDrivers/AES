//
//  AppDelegate.m
//  AES
//
//  Created by ldc on 2020/4/18.
//  Copyright © 2020 Xiamen Hanin. All rights reserved.
//

#import "AppDelegate.h"
#import "AES.h"

@interface AppDelegate ()

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    
    NSString *key = @"12345678901234567890123456789012";
    NSString *origin = @"1234567890";
    AES *aes = [[AES alloc] init];
    [aes configureOptions:AESOptionsECBMode | AESOptionsPKCS7Padding key:key vi:nil];
    NSData *originData = [origin dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"加密输入数据: %@ => 长度: %lu", originData, originData.length);
    NSData *encryptData = [aes encrypt:originData];
    NSLog(@"加密数据: %@ => 长度: %lu", encryptData, encryptData.length);
    NSLog(@"加密base64: %@", [encryptData base64EncodedStringWithOptions:0]);
    NSData *decryptData = [aes decrypt:encryptData];
    NSLog(@"解密数据: %@ => 长度: %lu", decryptData, decryptData.length);
    NSString *descryptTxt = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    NSLog(@"解密字符: %@", descryptTxt);
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}


@end
