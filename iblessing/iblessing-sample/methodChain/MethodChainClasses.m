//
//  MethodChainClasses.m
//  iblessing-sample
//
//  Created by soulghost on 2020/7/25.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import "MethodChainClasses.h"

typedef void (^BlockWithMixedArgsV1)(NSString *a, BOOL b, id c, IBSRoot *d, BlockSubA *e, BlockSubB *f);
typedef NSString* (^BlockWithMixedArgsV2)(int a, BlockSubB *b, BOOL c, BOOL *d, int *e, Class f, BlockSubA *g);

@implementation IBSRoot

+ (void)rootClassMethodCallFromPrimary {
    
}

+ (void)rootClassMethodCallFromReflection {
    
}

+ (void)rootClassMethodCallFromInstanceClass {
    
}

+ (void)rootClassMethodCallFromBlockArgs {
    
}

+ (void)rootClassMethodCallFromCategoryMethod {
    
}

- (void)rootInstanceMethodCallFromIvar {
    
}

- (void)rootInstanceMethodCallFromAllocate {
    
}

- (void)rootInstanceMethodCallFromBlockArgs {
    
}

- (void)rootInstanceMethodFromBranchTrue {
    
}

- (void)rootInstanceMethodFromBranchFalse {
    
}

- (void)rootInstanceMethodFromSwitchTableA {
    
}

- (void)rootInstanceMethodFromSwitchTableB {
    
}

- (void)rootInstanceMethodFromSwitchTableC {
    
}

- (void)rootInstanceMethodWithStaticArgSnapshot:(BOOL)a str:(NSString *)str dict:(NSDictionary *)c d:(NSInteger)d f:(IBSCallTester *)f g:(InstanceObject *)g {
    
}

struct PrimaryStruct {
    int a;
    int b;
    char *c;
};

- (void)rootInstanceMethodWithOCObjectConstOCStringVal:(NSString *)constOCStringVal constOCDictVal:(NSDictionary *)constOCDictVal  dynamicOCStringVal:(NSString *)dynamicOCStringVal dynamicOCDict:(NSDictionary *)dynamicOCDictVal selfInput:(IBSCallTester *)selfInputVal localAllocate:(InstanceObject *)localAllocateVal {
    
}

- (void)rootInstanceMethodWithPrimaryBOOL:(BOOL)boolVal primaryInt:(int)intVal primaryFloat:(float)floatVal primaryDouble:(double)doubleVal {
    
}

- (void)rootInstanceMethodWithCTypesPrimaryStruct:(struct PrimaryStruct)structVal primaryStructPtr:(struct PrimaryStruct *)primaryStructPtrVal rawPtrVal:(void *)rawPtrVal constCString:(const char *)constCStringVal dynamicCString:(char *)dynamicCStringVal {
    
}

@end


@implementation IBSCallTester

+ (void)testPrimaryCallToRootClassMethodAncestor {
    [IBSRoot rootClassMethodCallFromPrimary];
}

+ (void)testReflectionCallToRootClassMethodAncestor {
    [NSClassFromString(@"IBSRoot") rootClassMethodCallFromReflection];
}

+ (void)testInstanceCallToRootClassMethodAncestor {
    [[[[IBSRoot alloc] init] class] rootClassMethodCallFromInstanceClass];
}

- (void)testSelfCall {
    [self selfCallChain1];
}

- (void)selfCallChain1 {
    [self selfCallChain2];
}

- (void)selfCallChain2 {
    [self selfCallChain3];
}

- (void)selfCallChain3 {
    NSLog(@"self call end");
}

- (void)testLoop {
    [self testLoop];
}

- (void)testAllocateCall {
    IBSRoot *root = [[IBSRoot alloc] init];
    [root rootInstanceMethodCallFromAllocate];
}

- (void)testIvarCall {
    [self.root rootInstanceMethodCallFromIvar];
}

- (void)localStackBlockInovker:(void (^)(BlockSubA *sub))callback {
    callback([BlockSubA new]);
}

- (void)localStackBlockInvoker2:(BlockWithMixedArgsV1)callback {
    
}

- (void)localStackBlockInvoker3:(BlockWithMixedArgsV2)callback {
    
}

- (void)testSelfCapture {
    
}

- (void)testLocalBlockOnStack {
    BlockSubA *allocateCapture = [BlockSubA new];
    [self localStackBlockInovker:^(BlockSubA *sub) {
        [allocateCapture testAllocateCapture];
        [self testSelfCapture];
        [sub testCallFromBlockArg];
    }];
}

- (void)testSystemBlockOnStack {
    BlockSubA *allocateCapture = [BlockSubA new];
    [@[@1, @2, @3] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [allocateCapture testAllocateCapture];
        [self testSelfCapture];
    }];
}

- (void)testMixedBlockOnStack {
    [self localStackBlockInvoker2:^(NSString *a, BOOL b, id c, IBSRoot *d, BlockSubA *e, BlockSubB *f) {
        [[d class] rootClassMethodCallFromBlockArgs];
        [d rootInstanceMethodCallFromBlockArgs];
        [e testCallFromBlockArg];
        [f testCallFromblockArg];
        [self testSelfCapture];
    }];

    [self localStackBlockInvoker3:^NSString *(int a, BlockSubB *b, BOOL c, BOOL *d, int *e, __unsafe_unretained Class f, BlockSubA *g) {
        [b testCallFromblockArg];
        [g testCallFromBlockArg];
        [self testSelfCapture];
        return @"xxx";
    }];
}

- (void)testCategoryCall {
    CategoryObject *cate = [CategoryObject new];
    [cate callFromInstance];
    [CategoryObject callFromClass];
}

- (void)testCallToCollectSnapshot {
    IBSRoot *root = [IBSRoot new];
    InstanceObject *localAllocate = [InstanceObject new];
    NSDictionary *dict = @{@"foo": @"bar", @"type": @"immutablez"};
    NSMutableDictionary *mutableDict = @{@"type": @"mutable"}.mutableCopy;
    [mutableDict setObject:@"foo" forKey:@"bar"];
    
    NSMutableString *dynamicString = @"dynamic string".mutableCopy;
    [dynamicString appendString:@"any"];
    
    char *dynamicCString = strdup("dynamic c string");
    
    struct PrimaryStruct primaryStruct = {.a = 0xaaaa, .b = 0xbbbb, .c = "primaryStruct"};
    void *rawPtr = malloc(0x1024);
    
    [root rootInstanceMethodWithPrimaryBOOL:YES
                                 primaryInt:0xaaaa
                               primaryFloat:M_PI
                              primaryDouble:M_PI_2];
    
    [root rootInstanceMethodWithCTypesPrimaryStruct:primaryStruct
                                   primaryStructPtr:&primaryStruct
                                          rawPtrVal:rawPtr
                                       constCString:"const c string"
                                     dynamicCString:dynamicCString];
    
    [root rootInstanceMethodWithOCObjectConstOCStringVal:@"const oc string"
                                          constOCDictVal:dict
                                      dynamicOCStringVal:dynamicString.copy
                                           dynamicOCDict:mutableDict.copy
                                               selfInput:self
                                           localAllocate:localAllocate];
}

@end

@implementation BlockSubA

- (void)testAllocateCapture {
    
}

- (void)testCallFromBlockArg {
    
}

@end

@implementation BlockSubB

- (void)testCallFromblockArg {
    
}

@end

@implementation BranchCall

- (void)simpleBranchCallWithoutLoop {
    uint32_t rand = arc4random_uniform(1000);
    IBSRoot *root = [[IBSRoot alloc] init];
    if (rand < 500) {
        TrapObject *trap = [[TrapObject alloc] init];
        [root rootInstanceMethodFromBranchTrue];
        root = trap;
        if (rand < 200) {
            printf("this tap\n");
            if (rand < 100) {
                printf("that tap\n");
            }
        }
    } else {
        [root rootInstanceMethodFromBranchFalse];
    }
}

//- (void)simpleBranchCallWithLoop {
//    uint32_t rand = arc4random_uniform(1000);
//    IBSRoot *root = [[IBSRoot alloc] init];
//    while (arc4random_uniform(10000) < 5000) {
//        if (rand < 500) {
//            TrapObject *trap = [[TrapObject alloc] init];
//            [root rootInstanceMethodFromBranchTrue];
//        } else {
//            TrapObject *trap = [[TrapObject alloc] init];
//            [root rootInstanceMethodFromBranchFalse];
//        }
//    }
//}

@end

@implementation TrapObject

@end

@implementation CategoryObject

@end

@implementation CategoryObject (Addon)

- (void)callFromInstance {
    NSLog(@"instance");
}

+ (void)callFromClass {
    NSLog(@"class");
}

- (void)cateCallToOut {
    [IBSRoot rootClassMethodCallFromCategoryMethod];
}

@end

@implementation InstanceObject

@end
