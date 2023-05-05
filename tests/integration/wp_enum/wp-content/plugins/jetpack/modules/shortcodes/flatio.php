<?php
/**
 * Flat.io embed
 *
 * Example URL: https://flat.io/score/5a5268ed41396318cbd7772c-string-quartet-for-rainy-days
 *
 * @package automattic/jetpack
 */

// Register oEmbed provider.
wp_oembed_add_provider( 'https://flat.io/score/*', 'https://flat.io/services/oembed', false );
wp_oembed_add_provider( 'https://*.flat.io/score/*', 'https://flat.io/services/oembed', false );
