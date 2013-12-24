// Created by Noah Martin
// http://noahmart.in

#import "NSData+AES128.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (AES128)

-(NSData*)AES128DecryptWithKey:(NSString*)key
{
    NSMutableData *mutableData = [NSMutableData dataWithData:self];
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [mutableData length];
    int excess = dataLength % 16;
    if(excess) {
        int padding = 16 - excess;
        [mutableData increaseLengthBy:padding];
        dataLength += padding;
    }
    NSMutableData *returnData = [[NSMutableData alloc] init];
    int bufferSize = 16;
    int start = 0;
    int i = 0;
    while(start < dataLength)
    {
        i++;
        void *buffer = malloc(bufferSize);
        size_t numBytesDecrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, 0,
                                              keyPtr, kCCKeySizeAES128,
                                              NULL,
                                              [[mutableData subdataWithRange:NSMakeRange(start, bufferSize)] bytes], bufferSize,
                                              buffer, bufferSize,
                                              &numBytesDecrypted);
        if (cryptStatus == kCCSuccess) {
            NSData *piece = [NSData dataWithBytes:buffer length:numBytesDecrypted];
            [returnData appendData:piece];
        }
        free(buffer);
        start += bufferSize;
    }
    return returnData;
}

-(NSData*)AES128EncryptWithKey:(NSString *)key
{
    NSMutableData *mutableData = [NSMutableData dataWithData:self];
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [mutableData length];
    int excess = dataLength % 16;
    if(excess) {
        int padding = 16 - excess;
        [mutableData increaseLengthBy:padding];
        dataLength += padding;
    }
    NSMutableData *returnData = [[NSMutableData alloc] init];
    int bufferSize = 16;
    int start = 0;
    int i = 0;
    while(start < dataLength)
    {
        i++;
        void *buffer = malloc(bufferSize);
        size_t numBytesDecrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0,
                                              keyPtr, kCCKeySizeAES128,
                                              NULL,
                                              [[mutableData subdataWithRange:NSMakeRange(start, bufferSize)] bytes], bufferSize,
                                              buffer, bufferSize,
                                              &numBytesDecrypted);
        if (cryptStatus == kCCSuccess) {
            NSData *piece = [NSData dataWithBytes:buffer length:numBytesDecrypted];
            [returnData appendData:piece];
        }
        free(buffer);
        start += bufferSize;
    }
    return returnData;
    return nil;
}

@end
