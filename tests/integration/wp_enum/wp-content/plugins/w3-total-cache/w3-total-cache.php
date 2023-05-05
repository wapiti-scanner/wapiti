<?php
/**
 * Plugin Name:       W3 Total Cache
 * Plugin URI:        https://www.boldgrid.com/totalcache/
 * Description:       The highest rated and most complete WordPress performance plugin. Dramatically improve the speed and user experience of your site. Add browser, page, object and database caching as well as minify and content delivery network (CDN) to WordPress.
 * Version:           2.3.1
 * Requires at least: 5.3
 * Requires PHP:      5.6
 * Author:            BoldGrid
 * Author URI:        https://www.boldgrid.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       w3-total-cache
 * Network:           True
 *
 * phpcs:disable Squiz.Commenting.FileComment.MissingPackageTag
 */

/*
 * Copyright (c) 2009 Frederick Townes <ftownes@w3-edge.com>
 * Portions of this distribution are copyrighted by:
 * Copyright (c) 2008 Ryan Grove <ryan@wonko.com>
 * Copyright (c) 2008 Steve Clay <steve@mrclay.org>
 * Copyright (c) 2007 Matt Mullenweg
 * Copyright (c) 2007 Andy Skelton
 * Copyright (c) 2007 Iliya Polihronov
 * Copyright (c) 2007 Michael Adams
 * Copyright (c) 2007 Automattic Inc.
 * Ryan Boren
 * All rights reserved.
 *
 * W3 Total Cache is distributed under the GNU General Public License, Version 2,
 * June 1991. Copyright (C) 1989, 1991 Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110, USA
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

if ( ! defined( 'ABSPATH' ) ) {
	die();
}

// Abort W3TC loading if WordPress is upgrading.
if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) {
	return;
}

if ( version_compare( PHP_VERSION, '5.6', '<' ) ) {
	require_once __DIR__ . '/w3-total-cache-old-php.php';
	register_activation_hook( __FILE__, 'w3tc_old_php_activate' );
	return;
}

if ( ! defined( 'W3TC_IN_MINIFY' ) ) {
	// Require plugin configuration.
	require_once __DIR__ . '/w3-total-cache-api.php';

	// Load the wp cli command - if run from wp-cli.
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		require_once W3TC_DIR . '/Cli.php';
	}

	// Include to prevent syntax error for older php.
	require_once __DIR__ . '/Root_Loader.php';
}
