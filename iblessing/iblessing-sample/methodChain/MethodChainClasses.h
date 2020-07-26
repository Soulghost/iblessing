//
//  MethodChainClasses.h
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface IBSRoot : NSObject

+ (void)rootClassMethodCallFromPrimary;
+ (void)rootClassMethodCallFromInstanceClass;
+ (void)rootClassMethodCallFromReflection;
- (void)rootInstanceMethodCallFromAllocate;
- (void)rootInstanceMethodCallFromIvar;

@end

@interface IBSCallTester : NSObject

@property (nonatomic, assign) int paddingEvil1;
@property (nonatomic, assign) char paddingEvil12;
@property (nonatomic, strong) IBSRoot *root;
@property (nonatomic, assign) char paddingEvil2;
@property (nonatomic, assign) bool paddingEvil3;

+ (void)testPrimaryCallToRootClassMethodAncestor;
+ (void)testReflectionCallToRootClassMethodAncestor;
+ (void)testInstanceCallToRootClassMethodAncestor;
- (void)selfCallChain1;
- (void)selfCallChain2;
- (void)selfCallChain3;
- (void)testLoop;

- (void)testIvarCall;
- (void)testAllocateCall;

@end
