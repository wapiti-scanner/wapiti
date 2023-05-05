<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Config\ScriptsConfig;
class AssetHelper
{
    private static $prefix = 'wordproof-';
    private static $filePath = 'app/';
    private static $buildPath = 'build/';
    /**
     * Localizes script by name.
     *
     * @param string $name Name of the script
     * @param string $objectName The name of the object in Javascript.
     * @param array $data The data to be included.
     * @return bool|void
     */
    public static function localize($name, $objectName, $data)
    {
        $config = \YoastSEO_Vendor\WordProof\SDK\Config\ScriptsConfig::get($name);
        if (!isset($config)) {
            return;
        }
        return \wp_localize_script(self::getHandle($name), $objectName, $data);
    }
    /**
     * Enqueues a script defined in the scripts config.
     *
     * @param string $name The name of the script to enqueue.
     * @return false|mixed|void
     */
    public static function enqueue($name)
    {
        $config = \YoastSEO_Vendor\WordProof\SDK\Config\ScriptsConfig::get($name);
        if (!isset($config)) {
            return;
        }
        $path = self::getPathUrl($name, $config['type']);
        if ($config['type'] === 'css') {
            \wp_enqueue_style(self::getHandle($name), $path, $config['dependencies'], self::getVersion());
        } else {
            \wp_enqueue_script(self::getHandle($name), $path, $config['dependencies'], self::getVersion(), \false);
        }
    }
    /**
     * Returns the prefixed script handle.
     *
     * @param string $name The name of the script.
     * @return string Handle of the script.
     */
    private static function getHandle($name)
    {
        return self::$prefix . $name;
    }
    /**
     * Get path url of the script.
     *
     * @param string $name The name of the script.
     * @return string The url of the script.
     */
    private static function getPathUrl($name, $extension)
    {
        $appConfig = \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getAppConfig();
        if ($appConfig->getScriptsFileOverwrite()) {
            $url = $appConfig->getScriptsFileOverwrite();
        } else {
            $url = \plugin_dir_url(WORDPROOF_TIMESTAMP_SDK_FILE);
        }
        $base = \YoastSEO_Vendor\WordProof\SDK\Helpers\StringHelper::lastReplace(self::$filePath, self::$buildPath, $url);
        return $base . $name . '.' . $extension;
    }
    /**
     * Returns version for file.
     *
     * @return false|string
     */
    private static function getVersion()
    {
        return \YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper::development() ? \false : WORDPROOF_TIMESTAMP_SDK_VERSION;
    }
}
