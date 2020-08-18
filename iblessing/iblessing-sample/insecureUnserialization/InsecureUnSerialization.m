//
//  InsecureUnSerialization.m
//  iblessing-sample
//
//  Created by soulghost on 2020/8/18.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "InsecureUnSerialization.h"

@implementation InsecureUnSerialization

- (int)insecureArchiverData {
    NSString *idx = @"comehere";
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [self insecureArchiverData];
    });
    
    
    [NSKeyedUnarchiver unarchiveObjectWithData:nil];
    
    return 1000;
}

- (void)insecureArchiverFile {
    [NSKeyedUnarchiver unarchiveObjectWithFile:nil];
}

- (void)insecureArchiverTopLevel {
    [NSKeyedUnarchiver unarchiveTopLevelObjectWithData:nil error:nil];


}

@end
