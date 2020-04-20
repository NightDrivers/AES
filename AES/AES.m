//
//  AES.m
//  AES
//
//  Created by ldc on 2020/4/18.
//  Copyright © 2020 Xiamen Hanin. All rights reserved.
//

#import "AES.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

NSData *AESKey(NSString *key) {
    
    NSData *data = [key dataUsingEncoding:NSASCIIStringEncoding];
    if (data) {
        NSUInteger length = data.length;
        if (length == kCCKeySizeAES128 || length == kCCKeySizeAES192 || length == kCCKeySizeAES256) {
            return data;
        }else {
            return nil;
        }
    }else {
        return nil;
    }
}

@interface AES ()

@property (nonatomic, strong) NSData *keyData;

@property (nonatomic, strong) NSData *viData;

@end

@implementation AES

- (void)setKey:(NSString *)key {
    
    NSData *temp = AESKey(key);
    if (!temp) {
        [NSException raise:@"不合格的密钥字符串,需要长度为16、24、32的ascii字符串" format:@""];
    }
    self.keyData = temp;
    _key = key;
}

- (void)setVi:(NSString *)vi {
    
    NSData *temp = [vi dataUsingEncoding:NSASCIIStringEncoding];
    if (temp) {
        if (temp.length == kCCBlockSizeAES128) {
            self.viData = temp;
            return;
        }else {
            [NSException raise:@"不合格的vi字符串,需要长度为16的ascii字符串" format:@""];
        }
    }
    self.viData = nil;
    _vi = vi;
}

- (void)configureOptions:(AESOptions)options key:(NSString *)key vi:(NSString *)vi {
    
    self.options = options;
    self.key = key;
    self.vi = vi;
}

- (NSData *)encrypt:(NSData *)data {
    
    NSInteger dataLength = ([data length] + kCCBlockSizeAES128)/kCCBlockSizeAES128*kCCBlockSizeAES128;
    void *bytes = calloc(dataLength, 1);
    [data getBytes:bytes length:[data length]];
    
    size_t bufferSize = dataLength;
    if ((self.options & AESOptionsPKCS7Padding) != 0) {
        dataLength = data.length;
    }
    NSLog(@"加密函数数据长度: %lu", dataLength);
    
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    
    CCCryptorStatus cryptStatus = CCCrypt(
                                          kCCEncrypt, 
                                          kCCAlgorithmAES128, 
                                          _options, 
                                          self.keyData.bytes, 
                                          self.keyData.length, 
                                          self.viData ? self.viData.bytes : NULL, 
                                          bytes, 
                                          dataLength, 
                                          buffer, 
                                          bufferSize, 
                                          &numBytesEncrypted
                                          );
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}

- (NSData *)decrypt:(NSData *)data {
    
    size_t bufferSize = ([data length] + kCCBlockSizeAES128)/kCCBlockSizeAES128*kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(
                                          kCCDecrypt, 
                                          kCCAlgorithmAES128,
                                          self.options,
                                          self.keyData.bytes, self.keyData.length,
                                          self.viData ? self.viData.bytes : NULL,
                                          [data bytes], 
                                          data.length,
                                          buffer, 
                                          bufferSize,
                                          &numBytesDecrypted
                                          );
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}

@end
