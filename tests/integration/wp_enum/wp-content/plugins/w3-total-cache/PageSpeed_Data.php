<?php
/**
 * File: PageSpeed_Data.php
 *
 * Processes PageSpeed API data return into usable format.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * PageSpeed Data Config.
 *
 * @since 2.3.0
 */
class PageSpeed_Data {

	/**
	 * Prepare PageSpeed Data Config.
	 *
	 * @since 2.3.0
	 *
	 * @param array $data PageSpeed analysis data.
	 *
	 * @return array
	 */
	public static function prepare_pagespeed_data( $data ) {
		return array(
			'score'                    => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'categories', 'performance', 'score' ) ) * 100,
			'first-contentful-paint'   => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint', 'displayValue' ) ),
			),
			'largest-contentful-paint' => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint', 'displayValue' ) ),
			),
			'interactive'              => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'interactive', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'interactive', 'displayValue' ) ),
			),
			'cumulative-layout-shift'  => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'cumulative-layout-shift', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'cumulative-layout-shift', 'displayValue' ) ),
			),
			'total-blocking-time'      => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-blocking-time', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-blocking-time', 'displayValue' ) ),
			),
			'speed-index'              => array(
				'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'speed-index', 'score' ) ),
				'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'speed-index', 'displayValue' ) ),
			),
			'screenshots'              => array(
				'final' => array(
					'title'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'final-screenshot', 'title' ) ),
					'screenshot' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'final-screenshot', 'details', 'data' ) ),
				),
				'other' => array(
					'title'       => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'screenshot-thumbnails', 'title' ) ),
					'screenshots' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'screenshot-thumbnails', 'details', 'items' ) ),
				),
			),
			'opportunities'            => array(
				'render-blocking-resources'    => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'render-blocking-resources', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'render-blocking-resources', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'render-blocking-resources', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'render-blocking-resources', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'render-blocking-resources', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'unused-css-rules'             => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-css-rules', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-css-rules', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-css-rules', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-css-rules', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-css-rules', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'unminified-css'               => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-css', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-css', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-css', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-css', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-css', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'unminified-javascript'        => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-javascript', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-javascript', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-javascript', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-javascript', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unminified-javascript', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'unused-javascript'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-javascript', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-javascript', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-javascript', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-javascript', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unused-javascript', 'details', 'items' ) ),
					'type'         => array(
						'LCP',
					),
				),
				'uses-responsive-images'       => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-responsive-images', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-responsive-images', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-responsive-images', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-responsive-images', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-responsive-images', 'details', 'items' ) ),
				),
				'offscreen-images'             => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'offscreen-images', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'offscreen-images', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'offscreen-images', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'offscreen-images', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'offscreen-images', 'details', 'items' ) ),
				),
				'uses-optimized-images'        => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-optimized-images', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-optimized-images', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-optimized-images', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-optimized-images', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-optimized-images', 'details', 'items' ) ),
				),
				'modern-image-formats'         => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'modern-image-formats', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'modern-image-formats', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'modern-image-formats', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'modern-image-formats', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'modern-image-formats', 'details', 'items' ) ),
				),
				'uses-text-compression'        => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-text-compression', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-text-compression', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-text-compression', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-text-compression', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-text-compression', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'uses-rel-preconnect'          => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preconnect', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preconnect', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preconnect', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preconnect', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preconnect', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'server-response-time'         => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'server-response-time', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'server-response-time', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'server-response-time', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'server-response-time', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'server-response-time', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'redirects'                    => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'redirects', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'redirects', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'redirects', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'redirects', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'redirects', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'uses-rel-preload'             => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preload', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preload', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preload', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preload', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-rel-preload', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'efficient-animated-content'   => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'efficient-animated-content', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'efficient-animated-content', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'efficient-animated-content', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'efficient-animated-content', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'efficient-animated-content', 'details', 'items' ) ),
					'type'         => array(
						'LCP',
					),
				),
				'duplicated-javascript'        => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'duplicated-javascript', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'duplicated-javascript', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'duplicated-javascript', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'duplicated-javascript', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'duplicated-javascript', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'legacy-javascript'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'legacy-javascript', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'legacy-javascript', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'legacy-javascript', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'legacy-javascript', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'legacy-javascript', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'preload-lcp-image'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'preload-lcp-image', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'preload-lcp-image', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'preload-lcp-image', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'preload-lcp-image', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'preload-lcp-image', 'details', 'items' ) ),
					'type'         => array(
						'LCP',
					),
				),
				'total-byte-weight'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-byte-weight', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-byte-weight', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-byte-weight', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-byte-weight', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'total-byte-weight', 'details', 'items' ) ),
					'type'         => array(
						'LCP',
					),
				),
				'dom-size'                     => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'dom-size', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'dom-size', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'dom-size', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'dom-size', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'dom-size', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'user-timings'                 => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'user-timings', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'user-timings', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'user-timings', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'user-timings', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'user-timings', 'details', 'items' ) ),
				),
				'bootup-time'                  => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'bootup-time', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'bootup-time', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'bootup-time', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'bootup-time', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'bootup-time', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'mainthread-work-breakdown'    => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'mainthread-work-breakdown', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'mainthread-work-breakdown', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'mainthread-work-breakdown', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'mainthread-work-breakdown', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'mainthread-work-breakdown', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'third-party-summary'          => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-summary', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-summary', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-summary', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-summary', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-summary', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'third-party-facades'          => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-facades', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-facades', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-facades', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-facades', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'third-party-facades', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
				'lcp-lazy-loaded'              => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'lcp-lazy-loaded', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'lcp-lazy-loaded', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'lcp-lazy-loaded', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'lcp-lazy-loaded', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'lcp-lazy-loaded', 'details', 'items' ) ),
				),
				'uses-passive-event-listeners' => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-passive-event-listeners', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-passive-event-listeners', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-passive-event-listeners', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-passive-event-listeners', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-passive-event-listeners', 'details', 'items' ) ),
				),
				'no-document-write'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'no-document-write', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'no-document-write', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'no-document-write', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'no-document-write', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'no-document-write', 'details', 'items' ) ),
				),
				'non-composited-animations'    => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'non-composited-animations', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'non-composited-animations', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'non-composited-animations', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'non-composited-animations', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'non-composited-animations', 'details', 'items' ) ),
					'type'         => array(
						'CLS',
					),
				),
				'unsized-images'               => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unsized-images', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unsized-images', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unsized-images', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unsized-images', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'unsized-images', 'details', 'items' ) ),
					'type'         => array(
						'CLS',
					),
				),
				'viewport'                     => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'viewport', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'viewport', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'viewport', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'viewport', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'viewport', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
			),
			'diagnostics'              => array(
				'font-display'                     => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'font-display', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'font-display', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'font-display', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'font-display', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'font-display', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'first-contentful-paint-3g'        => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint-3g', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint-3g', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint-3g', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint-3g', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'first-contentful-paint-3g', 'details', 'items' ) ),
				),
				'uses-long-cache-ttl'              => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-long-cache-ttl', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-long-cache-ttl', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-long-cache-ttl', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-long-cache-ttl', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'uses-long-cache-ttl', 'details', 'items' ) ),
				),
				'critical-request-chains'          => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'critical-request-chains', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'critical-request-chains', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'critical-request-chains', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'critical-request-chains', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'critical-request-chains', 'details', 'items' ) ),
					'type'         => array(
						'FCP',
						'LCP',
					),
				),
				'resource-summary'                 => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'resource-summary', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'resource-summary', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'resource-summary', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'resource-summary', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'resource-summary', 'details', 'items' ) ),
				),
				'largest-contentful-paint-element' => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint-element', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint-element', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint-element', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint-element', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'largest-contentful-paint-element', 'details', 'items' ) ),
					'type'         => array(
						'LCP',
					),
				),
				'layout-shift-elements'            => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'layout-shift-elements', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'layout-shift-elements', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'layout-shift-elements', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'layout-shift-elements', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'layout-shift-elements', 'details', 'items' ) ),
					'type'         => array(
						'CLS',
					),
				),
				'long-tasks'                       => array(
					'title'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'long-tasks', 'title' ) ),
					'description'  => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'long-tasks', 'description' ) ),
					'score'        => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'long-tasks', 'score' ) ),
					'displayValue' => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'long-tasks', 'displayValue' ) ),
					'details'      => Util_PageSpeed::get_value_recursive( $data, array( 'lighthouseResult', 'audits', 'long-tasks', 'details', 'items' ) ),
					'type'         => array(
						'TBT',
					),
				),
			),
		);
	}
}
