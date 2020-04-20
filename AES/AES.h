//
//  AES.h
//  AES
//
//  Created by ldc on 2020/4/18.
//  Copyright © 2020 Xiamen Hanin. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_OPTIONS(uint32_t, AESOptions) {
    AESOptionsPKCS7Padding = 1 << 0,///无填充或PKCS7填充
    AESOptionsECBMode = 1 << 1,/// CBC模式或ECB模式
};

@interface AES : NSObject

@property (nonatomic, assign) AESOptions options;

@property (nonatomic, copy) NSString *key;

@property (nonatomic, copy) NSString *vi;

/// 配置加密参数
/// @param options 可选项
/// @param key 密钥,16 24或32长度的ascii字符串
/// @param vi 偏移量，长度为16的ascii字符串，ECB模式可为空
- (void)configureOptions:(AESOptions)options key:(NSString *)key vi:(NSString * _Nullable)vi;

- (NSData *)encrypt:(NSData *)data;

- (NSData *)decrypt:(NSData *)data;

@end

NS_ASSUME_NONNULL_END
