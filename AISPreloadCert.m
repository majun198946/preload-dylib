// AISPreloadCert.m —— 零点击版：App 启动时自己把预置证书导入
//
// 原理：不碰全能签的 RSA/cert 那套（私钥不是我们的，复制不了），
//       而是调用它自己公开的 ObjC 方法：
//         -[X importCertificateBundleFromZipURL:password:presenter:error:]
//       这个方法是它"证书兑换/导入"内部用的，参数正好是
//       { zip(p12 + mobileprovision), 密码, 当前 VC, &error }。
//       所以只要在启动时喂我们自己的 zip，效果和用户手动导入完全一样。
//
// 依赖的资源（repack_preload.sh 已经放进包根目录）：
//   preload_cert.zip  —— cert.p12 + cert.mobileprovision
//   preload_cert.txt  —— p12 密码
//
// 编译：见 build_dylib.sh（需要 Xcode + iPhoneOS SDK）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *const kZipName  = @"preload_cert";
static NSString *const kDoneKey  = @"ais_preload_cert_done_v1";

#pragma mark - 找当前最顶层 VC

static UIViewController *AISTopViewController(void) {
    UIWindow *keyWin = nil;
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *w in ((UIWindowScene *)scene).windows) {
            if (w.isKeyWindow) { keyWin = w; break; }
        }
        if (keyWin) break;
    }
    if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;

    UIViewController *vc = keyWin.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if ([vc isKindOfClass:[UINavigationController class]])
        vc = ((UINavigationController *)vc).visibleViewController ?: vc;
    if ([vc isKindOfClass:[UITabBarController class]])
        vc = ((UITabBarController *)vc).selectedViewController ?: vc;
    return vc;
}

#pragma mark - 找实现了目标方法的类

static SEL kImportSel(void) {
    return NSSelectorFromString(@"importCertificateBundleFromZipURL:password:presenter:error:");
}

static Class AISFindImportClass(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return Nil;

    Class *list = (Class *)malloc(sizeof(Class) * (size_t)count);
    if (!list) return Nil;
    count = objc_getClassList(list, count);

    Class found = Nil;
    for (int i = 0; i < count; i++) {
        Class c = list[i];
        if (class_getInstanceMethod(c, kImportSel())) { found = c; break; }
    }
    free(list);
    return found;
}

static id AISInstanceFor(Class c) {
    for (NSString *n in @[@"sharedInstance", @"sharedManager", @"defaultManager",
                          @"shared", @"manager", @"instance"]) {
        SEL s = NSSelectorFromString(n);
        if ([c respondsToSelector:s]) {
            id obj = ((id (*)(id, SEL))objc_msgSend)((id)c, s);
            if (obj) return obj;
        }
    }
    id obj = ((id (*)(id, SEL))objc_msgSend)((id)c, NSSelectorFromString(@"alloc"));
    if (obj) obj = ((id (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"init"));
    return obj;
}

#pragma mark - 真正干活

static void AISPreloadRun(void) {
    @autoreleasepool {
        NSUserDefaults *def = [NSUserDefaults standardUserDefaults];
        if ([def boolForKey:kDoneKey]) return;

        Class cls = AISFindImportClass();
        if (!cls) {
            NSLog(@"[preload] 没找到 importCertificateBundleFromZipURL 方法，放弃");
            return;
        }

        NSBundle *bundle = [NSBundle mainBundle];
        NSString *zipPath = [bundle pathForResource:kZipName ofType:@"zip"];
        NSString *txtPath = [bundle pathForResource:kZipName ofType:@"txt"];
        if (!zipPath) { NSLog(@"[preload] 包里没有 %@.zip", kZipName); return; }

        NSString *pwd = txtPath ? [NSString stringWithContentsOfFile:txtPath
                                                            encoding:NSUTF8StringEncoding
                                                               error:NULL] : @"";
        pwd = [pwd stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        UIViewController *presenter = AISTopViewController();
        if (!presenter) { NSLog(@"[preload] 没有 presenter，稍后重试"); return; }

        id target = AISInstanceFor(cls);
        if (!target) { NSLog(@"[preload] 无法创建导入对象"); return; }

        NSMethodSignature *sig = [target methodSignatureForSelector:kImportSel()];
        if (!sig) return;
        NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
        inv.target = target;
        inv.selector = kImportSel();

        NSURL *zipURL = [NSURL fileURLWithPath:zipPath];
        NSError *err = nil;
        NSError *__autoreleasing *errPtr = &err;
        id pwdObj = pwd ?: @"";
        id presenterObj = presenter;

        [inv setArgument:&zipURL       atIndex:2];
        [inv setArgument:&pwdObj      atIndex:3];
        [inv setArgument:&presenterObj atIndex:4];
        [inv setArgument:&errPtr      atIndex:5];
        [inv retainArguments];

        @try {
            [inv invoke];
        } @catch (NSException *e) {
            NSLog(@"[preload] 调用异常: %@", e);
            return;
        }

        BOOL ok = NO;
        if (sig.methodReturnLength > 0) {
            const char *rt = sig.methodReturnType;
            if (rt[0] == 'c' || rt[0] == 'B' || rt[0] == 'i') [inv getReturnValue:&ok];
        } else {
            ok = YES;
        }

        if (ok || !err) {
            [def setBool:YES forKey:kDoneKey];
            NSLog(@"[preload] 证书已导入（ok=%d, err=%@）", ok, err);
        } else {
            NSLog(@"[preload] 导入失败: %@", err);
            // 不写 done 标记，下次启动再试一次
        }
    }
}

// 启动后再执行，等 UI / 数据层就绪；失败的话重试两次
__attribute__((constructor))
static void AISPreloadEntry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (int i = 0; i < 3; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * (i + 1) * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                AISPreloadRun();
            });
        }
    });
}
