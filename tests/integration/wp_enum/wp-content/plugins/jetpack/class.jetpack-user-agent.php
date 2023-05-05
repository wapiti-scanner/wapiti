<?php
/**
 * Deprecated. Use Automattic\Jetpack\Device_Detection\User_Agent_Info instead.
 *
 * @package automattic/jetpack
 *
 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
 *
 * Note: we cannot get rid of the class and its methods yet as multiple plugins
 * still use it. See https://github.com/Automattic/jetpack/pull/16434/files#r667190852
 *
 * @phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
 * @phpcs:disable WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
 * @phpcs:disable WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase
 * @phpcs:disable WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
 * @phpcs:disable WordPress.Files.FileName
 */

use \Automattic\Jetpack\Device_Detection\User_Agent_Info;

/**
 * A class providing device properties detection.
 *
 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
 */
class Jetpack_User_Agent_Info {

	/**
	 * User_Agent_Info instance from the `jetpack-device-detection` package.
	 *
	 * @var User_Agent_Info
	 */
	private $ua_info;

	/**
	 * Report deprecation if appropriate.
	 *
	 * Currently we don't when running on WordPress.com, as there's still a lot
	 * there that needs cleaning up first.
	 *
	 * @param string $method Method.
	 * @param string $repl Replacement method.
	 */
	private static function warn_deprecated( $method, $repl ) {
		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Strings passed are safe.
			_deprecated_function( $method, 'Jetpack 8.7', "\\Automattic\\Jetpack\\Device_Detection\\User_Agent_Info$repl from the `automattic/jetpack-device-detection` package" );
		}
	}

	/**
	 * The constructor.
	 *
	 * @param string $ua (Optional) User agent.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public function __construct( $ua = '' ) {
		self::warn_deprecated( __METHOD__, '' );
		$this->ua_info = new User_Agent_Info( $ua );
	}

	/**
	 * This method detects the mobile User Agent name.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return string The matched User Agent name, false otherwise.
	 */
	public function get_mobile_user_agent_name() {
		self::warn_deprecated( __METHOD__, '->get_mobile_user_agent_name' );
		return $this->ua_info->get_mobile_user_agent_name();
	}

	/**
	 * This method detects the mobile device's platform. All return strings are from the class constants.
	 * Note that this function returns the platform name, not the UA name/type. You should use a different function
	 * if you need to test the UA capabilites.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return string Name of the platform, false otherwise.
	 */
	public function get_platform() {
		self::warn_deprecated( __METHOD__, '->get_platform' );
		return $this->ua_info->get_platform();
	}

	/**
	 * This method detects for UA which can display iPhone-optimized web content.
	 * Includes iPhone, iPod Touch, Android, WebOS, Fennec (Firefox mobile), etc.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public function isTierIphone() {
		self::warn_deprecated( __METHOD__, '->isTierIphone' );
		return $this->ua_info->isTierIphone();
	}

	/**
	 * This method detects for UA which are likely to be capable
	 * but may not necessarily support JavaScript.
	 * Excludes all iPhone Tier UA.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public function isTierRichCss() {
		self::warn_deprecated( __METHOD__, '->isTierRichCss' );
		return $this->ua_info->isTierRichCss();
	}

	/**
	 * Detects if the user is using a tablet.
	 * props Corey Gilmore, BGR.com
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return bool
	 */
	public static function is_tablet() {
		self::warn_deprecated( __METHOD__, '->is_tablet' );
		return ( new User_Agent_Info() )->is_tablet();
	}

	/**
	 *  Detects if the current UA is the default iPhone or iPod Touch Browser.
	 *
	 *  @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_iphoneOrIpod() {
		self::warn_deprecated( __METHOD__, '->is_iphone_or_ipod' );
		return ( new User_Agent_Info() )->is_iphoneOrIpod();
	}

	/**
	 *  Detects if the current UA is iPhone Mobile Safari or another iPhone or iPod Touch Browser.
	 *
	 *  They type can check for any iPhone, an iPhone using Safari, or an iPhone using something other than Safari.
	 *
	 *  Note: If you want to check for Opera mini, Opera mobile or Firefox mobile (or any 3rd party iPhone browser),
	 *  you should put the check condition before the check for 'iphone-any' or 'iphone-not-safari'.
	 *  Otherwise those browsers will be 'catched' by the iphone string.
	 *
	 * @param string $type Type of iPhone detection.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_iphone_or_ipod( $type = 'iphone-any' ) {
		self::warn_deprecated( __METHOD__, '::is_iphone_or_ipod' );
		return User_Agent_Info::is_iphone_or_ipod( $type );
	}

	/**
	 *  Detects if the current UA is Chrome for iOS
	 *
	 *  The User-Agent string in Chrome for iOS is the same as the Mobile Safari User-Agent, with CriOS/<ChromeRevision> instead of Version/<VersionNum>.
	 *  - Mozilla/5.0 (iPhone; U; CPU iPhone OS 5_1_1 like Mac OS X; en) AppleWebKit/534.46.0 (KHTML, like Gecko) CriOS/19.0.1084.60 Mobile/9B206 Safari/7534.48.3
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_chrome_for_iOS() {
		self::warn_deprecated( __METHOD__, '::is_chrome_for_iOS' );
		return User_Agent_Info::is_chrome_for_iOS();
	}

	/**
	 *  Detects if the current UA is Twitter for iPhone
	 *
	 * Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_5 like Mac OS X; nb-no) AppleWebKit/533.17.9 (KHTML, like Gecko) Mobile/8L1 Twitter for iPhone
	 * Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/9B206 Twitter for iPhone
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_twitter_for_iphone() {
		self::warn_deprecated( __METHOD__, '::is_twitter_for_iphone' );
		return User_Agent_Info::is_twitter_for_iphone();
	}

	/**
	 * Detects if the current UA is Twitter for iPad
	 *
	 * Old version 4.X - Mozilla/5.0 (iPad; U; CPU OS 4_3_5 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Mobile/8L1 Twitter for iPad
	 * Ver 5.0 or Higher - Mozilla/5.0 (iPad; CPU OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/9B206 Twitter for iPhone
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_twitter_for_ipad() {
		self::warn_deprecated( __METHOD__, '::is_twitter_for_ipad' );
		return User_Agent_Info::is_twitter_for_ipad();
	}

	/**
	 * Detects if the current UA is Facebook for iPhone
	 * - Facebook 4020.0 (iPhone; iPhone OS 5.0.1; fr_FR)
	 * - Mozilla/5.0 (iPhone; U; CPU iPhone OS 5_0 like Mac OS X; en_US) AppleWebKit (KHTML, like Gecko) Mobile [FBAN/FBForIPhone;FBAV/4.0.2;FBBV/4020.0;FBDV/iPhone3,1;FBMD/iPhone;FBSN/iPhone OS;FBSV/5.0;FBSS/2; FBCR/O2;FBID/phone;FBLC/en_US;FBSF/2.0]
	 * - Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/9B206 [FBAN/FBIOS;FBAV/5.0;FBBV/47423;FBDV/iPhone3,1;FBMD/iPhone;FBSN/iPhone OS;FBSV/5.1.1;FBSS/2; FBCR/3ITA;FBID/phone;FBLC/en_US]
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_facebook_for_iphone() {
		self::warn_deprecated( __METHOD__, '::is_facebook_for_iphone' );
		return User_Agent_Info::is_facebook_for_iphone();
	}

	/**
	 * Detects if the current UA is Facebook for iPad
	 * - Facebook 4020.0 (iPad; iPhone OS 5.0.1; en_US)
	 * - Mozilla/5.0 (iPad; U; CPU iPhone OS 5_0 like Mac OS X; en_US) AppleWebKit (KHTML, like Gecko) Mobile [FBAN/FBForIPhone;FBAV/4.0.2;FBBV/4020.0;FBDV/iPad2,1;FBMD/iPad;FBSN/iPhone OS;FBSV/5.0;FBSS/1; FBCR/;FBID/tablet;FBLC/en_US;FBSF/1.0]
	 * - Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Mobile/10A403 [FBAN/FBIOS;FBAV/5.0;FBBV/47423;FBDV/iPad2,1;FBMD/iPad;FBSN/iPhone OS;FBSV/6.0;FBSS/1; FBCR/;FBID/tablet;FBLC/en_US]
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_facebook_for_ipad() {
		self::warn_deprecated( __METHOD__, '::is_facebook_for_ipad' );
		return User_Agent_Info::is_facebook_for_ipad();
	}

	/**
	 *  Detects if the current UA is WordPress for iOS.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_wordpress_for_ios() {
		self::warn_deprecated( __METHOD__, '::is_wordpress_for_ios' );
		return User_Agent_Info::is_wordpress_for_ios();
	}

	/**
	 * Detects if the current device is an iPad.
	 * They type can check for any iPad, an iPad using Safari, or an iPad using something other than Safari.
	 *
	 * Note: If you want to check for Opera mini, Opera mobile or Firefox mobile (or any 3rd party iPad browser),
	 * you should put the check condition before the check for 'iphone-any' or 'iphone-not-safari'.
	 * Otherwise those browsers will be 'catched' by the ipad string.
	 *
	 * @param string $type iPad type.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_ipad( $type = 'ipad-any' ) {
		self::warn_deprecated( __METHOD__, '::is_ipad' );
		return User_Agent_Info::is_ipad( $type );
	}

	/**
	 * Detects if the current browser is Firefox Mobile (Fennec)
	 *
	 * See http://www.useragentstring.com/pages/Fennec/
	 * Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.1.1) Gecko/20110415 Firefox/4.0.2pre Fennec/4.0.1
	 * Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1b2pre) Gecko/20081015 Fennec/1.0a1
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_firefox_mobile() {
		self::warn_deprecated( __METHOD__, '::is_firefox_mobile' );
		return User_Agent_Info::is_firefox_mobile();
	}

	/**
	 * Detects if the current browser is Firefox for desktop
	 *
	 * See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent/Firefox
	 * Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion
	 * The platform section will include 'Mobile' for phones and 'Tablet' for tablets.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_firefox_desktop() {
		self::warn_deprecated( __METHOD__, '::is_firefox_desktop' );
		return User_Agent_Info::is_firefox_desktop();
	}

	/**
	 * Detects if the current browser is FirefoxOS Native browser
	 *
	 * Mozilla/5.0 (Mobile; rv:14.0) Gecko/14.0 Firefox/14.0
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_firefox_os() {
		self::warn_deprecated( __METHOD__, '::is_firefox_os' );
		return User_Agent_Info::is_firefox_os();
	}

	/**
	 * Detects if the current browser is Opera Mobile
	 *
	 * What is the difference between Opera Mobile and Opera Mini?
	 * - Opera Mobile is a full Internet browser for mobile devices.
	 * - Opera Mini always uses a transcoder to convert the page for a small display.
	 * (it uses Opera advanced server compression technology to compress web content before it gets to a device.
	 *  The rendering engine is on Opera's server.)
	 *
	 * Opera/9.80 (Windows NT 6.1; Opera Mobi/14316; U; en) Presto/2.7.81 Version/11.00"
	 * Opera/9.50 (Nintendo DSi; Opera/507; U; en-US)
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_opera_mobile() {
		self::warn_deprecated( __METHOD__, '::is_opera_mobile' );
		return User_Agent_Info::is_opera_mobile();
	}

	/**
	 * Detects if the current browser is Opera Mini
	 *
	 * Opera/8.01 (J2ME/MIDP; Opera Mini/3.0.6306/1528; en; U; ssr)
	 * Opera/9.80 (Android;Opera Mini/6.0.24212/24.746 U;en) Presto/2.5.25 Version/10.5454
	 * Opera/9.80 (iPhone; Opera Mini/5.0.019802/18.738; U; en) Presto/2.4.15
	 * Opera/9.80 (J2ME/iPhone;Opera Mini/5.0.019802/886; U; ja) Presto/2.4.15
	 * Opera/9.80 (J2ME/iPhone;Opera Mini/5.0.019802/886; U; ja) Presto/2.4.15
	 * Opera/9.80 (Series 60; Opera Mini/5.1.22783/23.334; U; en) Presto/2.5.25 Version/10.54
	 * Opera/9.80 (BlackBerry; Opera Mini/5.1.22303/22.387; U; en) Presto/2.5.25 Version/10.54
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_opera_mini() {
		self::warn_deprecated( __METHOD__, '::is_opera_mini' );
		return User_Agent_Info::is_opera_mini();
	}

	/**
	 * Detects if the current browser is Opera Mini, but not on a smart device OS(Android, iOS, etc)
	 * Used to send users on dumb devices to m.wor
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_opera_mini_dumb() {
		self::warn_deprecated( __METHOD__, '::is_opera_mini_dumb' );
		return User_Agent_Info::is_opera_mini_dumb();
	}

	/**
	 * Detects if the current browser is Opera Mobile or Mini.
	 *
	 * Opera Mini 5 Beta: Opera/9.80 (J2ME/MIDP; Opera Mini/5.0.15650/756; U; en) Presto/2.2.0
	 * Opera Mini 8: Opera/8.01 (J2ME/MIDP; Opera Mini/3.0.6306/1528; en; U; ssr)
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_OperaMobile() {
		self::warn_deprecated( __METHOD__, '::is_opera_mini() or \Automattic\Jetpack\Device_Detection\User_Agent_Info::is_opera_mobile()' );
		return User_Agent_Info::is_OperaMobile();
	}

	/**
	 * Detects if the current browser is a Windows Phone 7 device.
	 * ex: Mozilla/4.0 (compatible; MSIE 7.0; Windows Phone OS 7.0; Trident/3.1; IEMobile/7.0; LG; GW910)
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_WindowsPhone7() {
		self::warn_deprecated( __METHOD__, '::is_WindowsPhone7' );
		return User_Agent_Info::is_WindowsPhone7();
	}

	/**
	 * Detects if the current browser is a Windows Phone 8 device.
	 * ex: Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; ARM; Touch; IEMobile/10.0; <Manufacturer>; <Device> [;<Operator>])
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_windows_phone_8() {
		self::warn_deprecated( __METHOD__, '::is_windows_phone_8' );
		return User_Agent_Info::is_windows_phone_8();
	}

	/**
	 * Detects if the current browser is on a Palm device running the new WebOS. This EXCLUDES TouchPad.
	 *
	 * Ex1: Mozilla/5.0 (webOS/1.4.0; U; en-US) AppleWebKit/532.2 (KHTML, like Gecko) Version/1.0 Safari/532.2 Pre/1.1
	 * Ex2: Mozilla/5.0 (webOS/1.4.0; U; en-US) AppleWebKit/532.2 (KHTML, like Gecko) Version/1.0 Safari/532.2 Pixi/1.1
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_PalmWebOS() {
		self::warn_deprecated( __METHOD__, '::is_PalmWebOS' );
		return User_Agent_Info::is_PalmWebOS();
	}

	/**
	 * Detects if the current browser is the HP TouchPad default browser. This excludes phones wt WebOS.
	 *
	 * TouchPad Emulator: Mozilla/5.0 (hp-desktop; Linux; hpwOS/2.0; U; it-IT) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.70 Safari/534.6 Desktop/1.0
	 * TouchPad: Mozilla/5.0 (hp-tablet; Linux; hpwOS/3.0.0; U; en-US) AppleWebKit/534.6 (KHTML, like Gecko) wOSBrowser/233.70 Safari/534.6 TouchPad/1.0
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_TouchPad() {
		self::warn_deprecated( __METHOD__, '::is_TouchPad' );
		return User_Agent_Info::is_TouchPad();
	}

	/**
	 * Detects if the current browser is the Series 60 Open Source Browser.
	 *
	 * OSS Browser 3.2 on E75: Mozilla/5.0 (SymbianOS/9.3; U; Series60/3.2 NokiaE75-1/110.48.125 Profile/MIDP-2.1 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413
	 *
	 * 7.0 Browser (Nokia 5800 XpressMusic (v21.0.025)) : Mozilla/5.0 (SymbianOS/9.4; U; Series60/5.0 Nokia5800d-1/21.0.025; Profile/MIDP-2.1 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413
	 *
	 * Browser 7.1 (Nokia N97 (v12.0.024)) : Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/12.0.024; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.12344
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_S60_OSSBrowser() {
		self::warn_deprecated( __METHOD__, '::is_S60_OSSBrowser' );
		return User_Agent_Info::is_S60_OSSBrowser();
	}

	/**
	 * Detects if the device platform is the Symbian Series 60.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_symbian_platform() {
		self::warn_deprecated( __METHOD__, '::is_symbian_platform' );
		return User_Agent_Info::is_symbian_platform();
	}

	/**
	 * Detects if the device platform is the Symbian Series 40.
	 * Nokia Browser for Series 40 is a proxy based browser, previously known as Ovi Browser.
	 * This browser will report 'NokiaBrowser' in the header, however some older version will also report 'OviBrowser'.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_symbian_s40_platform() {
		self::warn_deprecated( __METHOD__, '::is_symbian_s40_platform' );
		return User_Agent_Info::is_symbian_s40_platform();
	}

	/**
	 * Returns if the device belongs to J2ME capable family.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return bool
	 */
	public static function is_J2ME_platform() {
		self::warn_deprecated( __METHOD__, '::is_J2ME_platform' );
		return User_Agent_Info::is_J2ME_platform();
	}

	/**
	 * Detects if the current UA is on one of the Maemo-based Nokia Internet Tablets.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_MaemoTablet() {
		self::warn_deprecated( __METHOD__, '::is_MaemoTablet' );
		return User_Agent_Info::is_MaemoTablet();
	}

	/**
	 * Detects if the current UA is a MeeGo device (Nokia Smartphone).
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_MeeGo() {
		self::warn_deprecated( __METHOD__, '::is_MeeGo' );
		return User_Agent_Info::is_MeeGo();
	}

	/**
	 * The is_webkit() method can be used to check the User Agent for an webkit generic browser.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_webkit() {
		self::warn_deprecated( __METHOD__, '::is_webkit' );
		return User_Agent_Info::is_webkit();
	}

	/**
	 * Detects if the current browser is the Native Android browser.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean true if the browser is Android otherwise false
	 */
	public static function is_android() {
		self::warn_deprecated( __METHOD__, '::is_android' );
		return User_Agent_Info::is_android();
	}

	/**
	 * Detects if the current browser is the Native Android Tablet browser.
	 * Assumes 'Android' should be in the user agent, but not 'mobile'
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean true if the browser is Android and not 'mobile' otherwise false
	 */
	public static function is_android_tablet() {
		self::warn_deprecated( __METHOD__, '::is_android_tablet' );
		return User_Agent_Info::is_android_tablet();
	}

	/**
	 * Detects if the current browser is the Kindle Fire Native browser.
	 *
	 * Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us; Silk/1.1.0-84) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16 Silk-Accelerated=true
	 * Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; en-us; Silk/1.1.0-84) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16 Silk-Accelerated=false
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean true if the browser is Kindle Fire Native browser otherwise false
	 */
	public static function is_kindle_fire() {
		self::warn_deprecated( __METHOD__, '::is_kindle_fire' );
		return User_Agent_Info::is_kindle_fire();
	}

	/**
	 * Detects if the current browser is the Kindle Touch Native browser
	 *
	 * Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean true if the browser is Kindle monochrome Native browser otherwise false
	 */
	public static function is_kindle_touch() {
		self::warn_deprecated( __METHOD__, '::is_kindle_touch' );
		return User_Agent_Info::is_kindle_touch();
	}

	/**
	 * Detect if user agent is the WordPress.com Windows 8 app (used ONLY on the custom oauth stylesheet)
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_windows8_auth() {
		self::warn_deprecated( __METHOD__, '::is_windows8_auth' );
		return User_Agent_Info::is_windows8_auth();
	}

	/**
	 * Detect if user agent is the WordPress.com Windows 8 app.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_wordpress_for_win8() {
		self::warn_deprecated( __METHOD__, '::is_wordpress_for_win8' );
		return User_Agent_Info::is_wordpress_for_win8();
	}

	/**
	 * Detect if user agent is the WordPress.com Desktop app.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_wordpress_desktop_app() {
		self::warn_deprecated( __METHOD__, '::is_wordpress_desktop_app' );
		return User_Agent_Info::is_wordpress_desktop_app();
	}

	/**
	 * The is_blackberry_tablet() method can be used to check the User Agent for a RIM blackberry tablet.
	 * The user agent of the BlackBerry® Tablet OS follows a format similar to the following:
	 * Mozilla/5.0 (PlayBook; U; RIM Tablet OS 1.0.0; en-US) AppleWebKit/534.8+ (KHTML, like Gecko) Version/0.0.1 Safari/534.8+
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_blackberry_tablet() {
		self::warn_deprecated( __METHOD__, '::is_blackberry_tablet' );
		return User_Agent_Info::is_blackberry_tablet();
	}

	/**
	 * The is_blackbeberry() method can be used to check the User Agent for a blackberry device.
	 * Note that opera mini on BB matches this rule.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_blackbeberry() {
		self::warn_deprecated( __METHOD__, '::is_blackbeberry' );
		return User_Agent_Info::is_blackbeberry();
	}

	/**
	 * The is_blackberry_10() method can be used to check the User Agent for a BlackBerry 10 device.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_blackberry_10() {
		self::warn_deprecated( __METHOD__, '::is_blackberry_10' );
		return User_Agent_Info::is_blackberry_10();
	}

	/**
	 * Retrieve the blackberry OS version.
	 *
	 * Return strings are from the following list:
	 * - blackberry-10
	 * - blackberry-7
	 * - blackberry-6
	 * - blackberry-torch //only the first edition. The 2nd edition has the OS7 onboard and doesn't need any special rule.
	 * - blackberry-5
	 * - blackberry-4.7
	 * - blackberry-4.6
	 * - blackberry-4.5
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return string Version of the BB OS. If version is not found, get_blackbeberry_OS_version will return boolean false.
	 */
	public static function get_blackbeberry_OS_version() {
		self::warn_deprecated( __METHOD__, '::get_blackbeberry_OS_version' );
		return User_Agent_Info::get_blackbeberry_OS_version();
	}

	/**
	 * Retrieve the blackberry browser version.
	 *
	 * Return string are from the following list:
	 * - blackberry-10
	 * - blackberry-webkit
	 * - blackberry-5
	 * - blackberry-4.7
	 * - blackberry-4.6
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return string Type of the BB browser. If browser's version is not found, detect_blackbeberry_browser_version will return boolean false.
	 */
	public static function detect_blackberry_browser_version() {
		self::warn_deprecated( __METHOD__, '::detect_blackberry_browser_version' );
		return User_Agent_Info::detect_blackberry_browser_version();
	}

	/**
	 * Checks if a visitor is coming from one of the WordPress mobile apps.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return bool
	 */
	public static function is_mobile_app() {
		self::warn_deprecated( __METHOD__, '::is_mobile_app' );
		return User_Agent_Info::is_mobile_app();
	}

	/**
	 * Detects if the current browser is Nintendo 3DS handheld.
	 *
	 * Example: Mozilla/5.0 (Nintendo 3DS; U; ; en) Version/1.7498.US
	 * can differ in language, version and region
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 */
	public static function is_Nintendo_3DS() {
		self::warn_deprecated( __METHOD__, '::is_Nintendo_3DS' );
		return User_Agent_Info::is_Nintendo_3DS();
	}

	/**
	 * Was the current request made by a known bot?
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean
	 */
	public static function is_bot() {
		self::warn_deprecated( __METHOD__, '::is_bot' );
		return User_Agent_Info::is_bot();
	}

	/**
	 * Is the given user-agent a known bot?
	 * If you want an is_bot check for the current request's UA, use is_bot() instead of passing a user-agent to this method.
	 *
	 * @param string $ua A user-agent string.
	 *
	 * @deprecated 8.7.0 Use Automattic\Jetpack\Device_Detection\User_Agent_Info
	 *
	 * @return boolean
	 */
	public static function is_bot_user_agent( $ua = null ) {
		self::warn_deprecated( __METHOD__, '::is_bot_user_agent' );
		return User_Agent_Info::is_bot_user_agent( $ua );
	}
}
