// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// sinete_authenticate evaluates the device-owner authentication policy (Touch ID
// with a passcode fallback). evaluatePolicy is asynchronous, so we pump the run
// loop on the calling thread (which must be the main thread) until the reply
// arrives — this lets the system present the prompt.
int sinete_authenticate(const char *reason, char **err) {
	@autoreleasepool {
		LAContext *ctx = [[LAContext alloc] init];
		LAPolicy policy = LAPolicyDeviceOwnerAuthentication;

		NSError *canErr = nil;
		if (![ctx canEvaluatePolicy:policy error:&canErr]) {
			if (err) {
				const char *m = canErr ? [[canErr localizedDescription] UTF8String]
				                       : "presence policy unavailable";
				*err = strdup(m);
			}
			return 0;
		}

		__block volatile int done = 0;
		__block int ok = 0;
		__block char *errmsg = NULL;
		NSString *nsReason = [NSString stringWithUTF8String:reason];

		[ctx evaluatePolicy:policy
		    localizedReason:nsReason
		              reply:^(BOOL success, NSError *evalErr) {
			ok = success ? 1 : 0;
			if (!success && evalErr) {
				errmsg = strdup([[evalErr localizedDescription] UTF8String]);
			}
			done = 1;
		}];

		while (!done) {
			CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
		}

		if (!ok) {
			if (err) *err = errmsg ? errmsg : strdup("user presence was not verified");
			else if (errmsg) free(errmsg);
			return 0;
		}
		if (errmsg) free(errmsg);
		return 1;
	}
}
