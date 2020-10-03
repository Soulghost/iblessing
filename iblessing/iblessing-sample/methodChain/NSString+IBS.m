//
//  NSString+IBS.m
//  iblessing-sample
//
//  Created by soulghost on 2020/10/3.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "NSString+IBS.h"

@implementation NSString (IBS)

- (NSString *)ibs_encoding {
    return [self stringByAppendingFormat:@"x"];
}

@end
