//
//  AppInfoScanner.hpp
//  iblessing
//
//  Created by soulghost on 2020/7/19.
//  Copyright © 2020 soulghost. All rights reserved.
//

#ifndef AppInfoScanner_hpp
#define AppInfoScanner_hpp

#include <iblessing-core/scanner/Scanner.hpp>

NS_IB_BEGIN

class AppInfoScanner : public Scanner {
public:
    AppInfoScanner(std::string name, std::string desc): Scanner(name, desc, false) {}
    
    virtual ~AppInfoScanner() {};
    virtual int start();

private:
    std::map<std::string, std::string> PrivacyMap = {
        {"NSBluetoothAlwaysUsageDescription", "Bluetooth"},
        {"NSBluetoothPeripheralUsageDescription", "Bluetooth"}, // Deprecated
        {"NSCalendarsUsageDescription", "Calendars"},
        {"NSRemindersUsageDescription", "Reminders"},
        {"NSCameraUsageDescription", "Camera"},
        {"NSMicrophoneUsageDescription", "Microphone"},
        {"NSContactsUsageDescription", "Contacts"},
        {"NSFaceIDUsageDescription", "FaceID"},
        // FIXME : macOS only?
        {"NSDesktopFolderUsageDescription", "DesktopFolder"},
        {"NSDocumentsFolderUsageDescription", "DocumentsFolder"},
        {"NSDownloadsFolderUsageDescription", "DownloadsFolder"},
        {"NSNetworkVolumesUsageDescription", "NetworkVolumes"},
        {"NSRemovableVolumesUsageDescription", "RemovableVolumes"},
        {"NSFileProviderPresenceUsageDescription", "FileProviderPresence"},
        {"NSFileProviderDomainUsageDescription", "FileProviderDomainUsage"},
        {"NSGKFriendListUsageDescription", "GameCenter"},
        {"NSHealthClinicalHealthRecordsShareUsageDescription", "HealthClinicalHealthRecordsShare"},
        {"NSHealthShareUsageDescription", "HealthShare"},
        {"NSHealthUpdateUsageDescription", "HealthUpdate"},
        {"NSHomeKitUsageDescription", "HomeKit"},
        {"NSLocationAlwaysAndWhenInUseUsageDescription", "LocationAlwaysAndWhenInUse"},
        {"NSLocationUsageDescription", "Location"},
        {"NSLocationWhenInUseUsageDescription", "LocationWhenInUse"},
        {"NSLocationTemporaryUsageDescription", "LocationTemporary"},
        {"NSLocationAlwaysUsageDescription", "LocationAlwaysUsage"},
        {"NSAppleMusicUsageDescription", "AppleMusic"},
        {"NSMotionUsageDescription", "Motion"},
        {"NSFallDetectionUsageDescription", "FallDetection"},
        {"NSLocalNetworkUsageDescription", "LocalNetwork"},
        {"NSNearbyInteractionUsageDescription", "NearbyInteraction"},
        {"NSNearbyInteractionAllowOnceUsageDescription", "NearbyInteractionAllowOnceUsage"},
        {"NFCReaderUsageDescription", "CReader"},
        {"NSPhotoLibraryAddUsageDescription", "PhotoLibraryAdd"},
        {"NSPhotoLibraryUsageDescription", "PhotoLibrary"},
        {"NSUserTrackingUsageDescription", "UserTracking"},
        {"NSAppleEventsUsageDescription", "AppleEvents"},
        {"NSSystemAdministrationUsageDescription", "SystemAdministration"},
        {"NSSensorKitUsageDescription", "SensorKit"},
        {"NSSiriUsageDescription", "Siri"},
        {"NSSpeechRecognitionUsageDescription", "SpeechRecognition"},
        {"NSVideoSubscriberAccountUsageDescription", "VideoSubscriber"}
    };
};

NS_IB_END

#endif /* AppInfoScanner_hpp */
