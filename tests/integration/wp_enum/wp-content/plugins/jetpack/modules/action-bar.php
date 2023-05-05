<?php
/**
 * Module Name: Action Bar (Experimental)
 * Module Description: An easy to use way for visitors to follow, like, and comment on your site.
 * Sort Order: 40
 * Recommendation Order: 18
 * First Introduced: 11.4
 * Requires Connection: Yes
 * Auto Activate: No
 * Module Tags: Social
 * Feature: Engagement
 * Additional Search Queries: adminbar, actionbar, comments, likes, follow, sharing
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Action_Bar;

return; // Return out early for now. The module is not ready for production yet.

( new Action_Bar() )->init(); // phpcs:ignore Squiz.PHP.NonExecutableCode.Unreachable
