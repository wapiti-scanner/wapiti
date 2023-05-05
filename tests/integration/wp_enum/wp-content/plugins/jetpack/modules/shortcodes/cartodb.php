<?php
/**
 * Carto (formerly CartoDB)
 *
 * Example URL: http://osm2.carto.com/viz/08aef918-94da-11e4-ad83-0e0c41326911/public_map
 *
 * possible patterns:
 * [username].carto.com/viz/[map-id]/public_map
 * [username].carto.com/viz/[map-id]/embed_map
 * [username].carto.com/viz/[map-id]/map
 * [organization].carto.com/u/[username]/viz/[map-id]/public_map
 * [organization].carto.com/u/[username]/viz/[map-id]/embed_map
 * [organization].carto.com/u/[username]/viz/[map-id]/map
 *
 * On July 8th, 2016 CartoDB changed its primary domain from cartodb.com to carto.com
 * So this shortcode still supports the cartodb.com domain for oembeds.
 *
 * @package automattic/jetpack
 */

wp_oembed_add_provider( '#https?://(?:www\.)?[^/^\.]+\.carto(db)?\.com/\S+#i', 'https://services.carto.com/oembed', true );
