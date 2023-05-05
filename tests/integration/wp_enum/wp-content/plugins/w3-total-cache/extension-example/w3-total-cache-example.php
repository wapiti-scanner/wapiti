<?php
/*
Plugin Name: W3 Total Cache Example Extension
Description: W3 Total Cache Example Extension
Version: 1.0
Plugin URI: https://www.w3-edge.com/wordpress-plugins/w3-total-cache/
Author: Frederick Townes
Author URI: http://www.linkedin.com/in/fredericktownes
Network: True
*/

/*  Copyright (c) 2009 Frederick Townes <ftownes@w3-edge.com>

	W3 Total Cache is distributed under the GNU General Public License, Version 2,
	June 1991. Copyright (C) 1989, 1991 Free Software Foundation, Inc., 51 Franklin
	St, Fifth Floor, Boston, MA 02110, USA

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
	ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

if ( !defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Class autoloader
 *
 * @param string  $class Classname
 */
function w3tc_example_class_autoload( $class ) {
	if ( substr( $class, 0, 12 ) == 'W3TCExample\\' ) {
		$filename = dirname( __FILE__ ) . DIRECTORY_SEPARATOR .
			substr( $class, 12 ) . '.php';

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			if ( !file_exists( $filename ) ) {
				debug_print_backtrace();
			}
		}

		require $filename;
	}
}

spl_autoload_register( 'w3tc_example_class_autoload' );

add_action( 'w3tc_extensions', array(
		'\W3TCExample\Extension_Example_Admin',
		'w3tc_extensions'
	), 10, 2 );
