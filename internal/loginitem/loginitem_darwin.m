// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

#import <ServiceManagement/ServiceManagement.h>
#import <Foundation/Foundation.h>
#include <stdlib.h>
#include <string.h>

// agentService resolves the bundled LaunchAgent plist by name. SMAppService reads
// it from the calling bundle's Contents/Library/LaunchAgents and validates the
// bundle's code signature, so these calls must run from the signed sinete.app.
static SMAppService *agentService(const char *plist) {
	return [SMAppService agentServiceWithPlistName:[NSString stringWithUTF8String:plist]];
}

int sinete_loginitem_register(const char *plist, char **err) {
	@autoreleasepool {
		NSError *e = nil;
		if ([agentService(plist) registerAndReturnError:&e]) {
			return 1;
		}
		if (err) {
			*err = strdup(e ? [[e localizedDescription] UTF8String] : "registration failed");
		}
		return 0;
	}
}

int sinete_loginitem_unregister(const char *plist, char **err) {
	@autoreleasepool {
		NSError *e = nil;
		if ([agentService(plist) unregisterAndReturnError:&e]) {
			return 1;
		}
		if (err) {
			*err = strdup(e ? [[e localizedDescription] UTF8String] : "unregistration failed");
		}
		return 0;
	}
}

// sinete_loginitem_status returns the SMAppServiceStatus enum: 0 not registered,
// 1 enabled, 2 requires approval, 3 not found.
int sinete_loginitem_status(const char *plist) {
	@autoreleasepool {
		return (int)[agentService(plist) status];
	}
}
