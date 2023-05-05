<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig;
class SettingsHelper
{
    private static $key = 'settings';
    /**
     * Retrieving settings from the option.
     *
     * @param null $setting The key for the setting
     * @return array|bool|int|mixed|object|string|null
     */
    public static function get($setting = null)
    {
        $settings = \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::get(self::$key);
        if ($setting) {
            $option = \YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig::get('settings.options.' . $setting);
            if (isset($settings->{$setting}) && $option) {
                return $settings->{$setting};
            }
            return $option['default'];
        }
        return (object) $settings;
    }
    public static function showRevisions()
    {
        return self::get('show_revisions');
    }
    public static function certificateLinkText()
    {
        return self::get('certificate_link_text');
    }
    public static function hideCertificateLink()
    {
        return self::get('hide_certificate_link');
    }
    public static function selectedPostTypes()
    {
        return \apply_filters('wordproof_timestamp_post_types', self::get('selected_post_types'));
    }
    public static function postTypeIsInSelectedPostTypes($postType)
    {
        $postTypes = self::selectedPostTypes();
        return \in_array($postType, $postTypes, \true);
    }
}
