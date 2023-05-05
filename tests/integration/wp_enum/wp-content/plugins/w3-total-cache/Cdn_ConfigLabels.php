<?php
namespace W3TC;

class Cdn_ConfigLabels {
	public function config_labels( $config_labels ) {
		return array_merge( $config_labels, array(
				'cdn.enabled' => __( '<acronym title="Content Delivery Network">CDN</acronym>:', 'w3-total-cache' ),
				'cdn.engine' => __( '<acronym title="Content Delivery Network">CDN</acronym> Type:', 'w3-total-cache' ),
				'cdn.debug' => __( '<acronym title="Content Delivery Network">CDN</acronym>', 'w3-total-cache' ),
				'cdnfsd.debug' => __( '<acronym title="Full Site Delivery">FSD</acronym> <acronym title="Content Delivery Network">CDN</acronym>', 'w3-total-cache' ),
				'cdn.uploads.enable' => __( 'Host attachments', 'w3-total-cache' ),
				'cdn.includes.enable' => __( 'Host wp-includes/ files', 'w3-total-cache' ),
				'cdn.theme.enable' => __( 'Host theme files', 'w3-total-cache' ),
				'cdn.minify.enable' => __( 'Host minified <acronym title="Cascading Style Sheet">CSS</acronym> and <acronym title="JavaScript">JS</acronym> files', 'w3-total-cache' ),
				'cdn.custom.enable' => __( 'Host custom files', 'w3-total-cache' ),
				'cdn.force.rewrite' => __( 'Force over-writing of existing files', 'w3-total-cache' ),
				'cdn.import.external' => __( 'Import external media library attachments', 'w3-total-cache' ),
				'cdn.canonical_header' => __( 'Add canonical header', 'w3-total-cache' ),
				'cdn.reject.ssl' => __( 'Disable <acronym title="Content Delivery Network">CDN</acronym> on <acronym title="Secure Sockets Layer">SSL</acronym> pages', 'w3-total-cache' ),
				'cdn.admin.media_library' => __( 'Use <acronym title="Content Delivery Network">CDN</acronym> links for the Media Library on admin pages', 'w3-total-cache' ),
				'cdn.reject.logged_roles' => __( 'Disable <acronym title="Content Delivery Network">CDN</acronym> for the following roles', 'w3-total-cache' ),
				'cdn.reject.uri' => __( 'Disable <acronym title="Content Delivery Network">CDN</acronym> on the following pages:', 'w3-total-cache' ),
				'cdn.autoupload.enabled' => __( 'Export changed files automatically', 'w3-total-cache' ),
				'cdn.autoupload.interval' => __( 'Auto upload interval:', 'w3-total-cache' ),
				'cdn.queue.interval' => __( 'Re-transfer cycle interval:', 'w3-total-cache' ),
				'cdn.queue.limit' => __( 'Re-transfer cycle limit:', 'w3-total-cache' ),
				'cdn.includes.files' => __( 'wp-includes file types to upload:', 'w3-total-cache' ),
				'cdn.theme.files' => __( 'Theme file types to upload:', 'w3-total-cache' ),
				'cdn.import.files' => __( 'File types to import:', 'w3-total-cache' ),
				'cdn.custom.files' => __( 'Custom file list:', 'w3-total-cache' ),
				'cdn.rscf.location' => __( 'Location:', 'w3-total-cache' ),
				'cdn.reject.ua' => __( 'Rejected user agents:', 'w3-total-cache' ),
				'cdn.reject.files' => __( 'Rejected files:', 'w3-total-cache' ),
			) );
	}
}
