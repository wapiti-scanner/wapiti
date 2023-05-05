<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * CSSTidy - CSS Parser and Optimiser
 *
 * CSS Parser class
 *
 * Copyright 2005, 2006, 2007 Florian Schmitz
 *
 * This file is part of CSSTidy.
 *
 *   CSSTidy is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   CSSTidy is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * @license https://opensource.org/licenses/lgpl-license.php GNU Lesser General Public License
 * @package csstidy
 * @author Florian Schmitz (floele at gmail dot com) 2005-2007
 * @author Brett Zamir (brettz9 at yahoo dot com) 2007
 * @author Nikolay Matsievsky (speed at webo dot name) 2009-2010
 * @author Cedric Morin (cedric at yterium dot com) 2010
 */

// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged

/**
 * Defines ctype functions if required
 *
 * @version 1.0
 */
require_once __DIR__ . '/class.csstidy-ctype.php';

/**
 * Various CSS data needed for correct optimisations etc.
 *
 * @version 1.3
 */
require __DIR__ . '/data.inc.php';

/**
 * Contains a class for printing CSS code
 *
 * @version 1.0
 */
require __DIR__ . '/class.csstidy-print.php';

/**
 * Contains a class for optimising CSS code
 *
 * @version 1.0
 */
require __DIR__ . '/class.csstidy-optimise.php';

/**
 * CSS Parser class

 * This class represents a CSS parser which reads CSS code and saves it in an array.
 * In opposite to most other CSS parsers, it does not use regular expressions and
 * thus has full CSS2 support and a higher reliability.
 * Additional to that it applies some optimisations and fixes to the CSS code.
 * An online version should be available here: https://cdburnerxp.se/cssparse/css_optimiser.php
 *
 * @package csstidy
 * @author Florian Schmitz (floele at gmail dot com) 2005-2006
 * @version 1.3.1
 */
#[AllowDynamicProperties]
class csstidy { // phpcs:ignore

	/**
	 * Saves the parsed CSS. This array is empty if preserve_css is on.
	 *
	 * @var array
	 * @access public
	 */
	public $css = array();
	/**
	 * Saves the parsed CSS (raw)
	 *
	 * @var array
	 * @access private
	 */
	public $tokens = array();
	/**
	 * Printer class
	 *
	 * @see csstidy_print
	 * @var object
	 * @access public
	 */
	public $print;
	/**
	 * Optimiser class
	 *
	 * @see csstidy_optimise
	 * @var object
	 * @access private
	 */
	public $optimise;
	/**
	 * Saves the CSS charset (@charset)
	 *
	 * @var string
	 * @access private
	 */
	public $charset = '';
	/**
	 * Saves all @import URLs
	 *
	 * @var array
	 * @access private
	 */
	public $import = array();
	/**
	 * Saves the namespace
	 *
	 * @var string
	 * @access private
	 */
	public $namespace = '';
	/**
	 * Contains the version of csstidy
	 *
	 * @var string
	 * @access private
	 */
	public $version = '1.3';
	/**
	 * Stores the settings
	 *
	 * @var array
	 * @access private
	 */
	public $settings = array();
	/**
	 * Saves the parser-status.
	 *
	 * Possible values:
	 * - is = in selector
	 * - ip = in property
	 * - iv = in value
	 * - instr = in string (started at " or ' or ( )
	 * - ic = in comment (ignore everything)
	 * - at = in @-block
	 *
	 * @var string
	 * @access private
	 */
	public $status = 'is';
	/**
	 * Saves the current at rule (@media)
	 *
	 * @var string
	 * @access private
	 */
	public $at = '';
	/**
	 * Saves the current selector
	 *
	 * @var string
	 * @access private
	 */
	public $selector = '';
	/**
	 * Saves the current property
	 *
	 * @var string
	 * @access private
	 */
	public $property = '';
	/**
	 * Saves the position of , in selectors
	 *
	 * @var array
	 * @access private
	 */
	public $sel_separate = array();
	/**
	 * Saves the current value
	 *
	 * @var string
	 * @access private
	 */
	public $value = '';
	/**
	 * Saves the current sub-value
	 *
	 * Example for a subvalue:
	 * background:url(foo.png) red no-repeat;
	 * "url(foo.png)", "red", and  "no-repeat" are subvalues,
	 * separated by whitespace
	 *
	 * @var string
	 * @access private
	 */
	public $sub_value = '';
	/**
	 * Array which saves all subvalues for a property.
	 *
	 * @var array
	 * @see sub_value
	 * @access private
	 */
	public $sub_value_arr = array();
	/**
	 * Saves the stack of characters that opened the current strings
	 *
	 * @var array
	 * @access private
	 */
	public $str_char = array();
	/**
	 * Current strings.
	 *
	 * @var array
	 * @access private
	 */
	public $cur_string = array();
	/**
	 * Status from which the parser switched to ic or instr
	 *
	 * @var array
	 * @access private
	 */
	public $from = array();
	/**
	/**
	 * =true if in invalid at-rule
	 *
	 * @var bool
	 * @access private
	 */
	public $invalid_at = false;
	/**
	 * =true if something has been added to the current selector
	 *
	 * @var bool
	 * @access private
	 */
	public $added = false;
	/**
	 * Array which saves the message log
	 *
	 * @var array
	 * @access private
	 */
	public $log = array();
	/**
	 * Saves the line number
	 *
	 * @var integer
	 * @access private
	 */
	public $line = 1;
	/**
	 * Marks if we need to leave quotes for a string
	 *
	 * @var array
	 * @access private
	 */
	public $quoted_string = array();

	/**
	 * List of tokens
	 *
	 * @var string
	 */
	public $tokens_list = '';

	/**
	 * Loads standard template and sets default settings.
	 *
	 * @access private
	 * @version 1.3
	 */
	public function __construct() {
		$this->settings['remove_bslash']        = true;
		$this->settings['compress_colors']      = true;
		$this->settings['compress_font-weight'] = true;
		$this->settings['lowercase_s']          = false;

		/*
		1 common shorthands optimization
		2 + font property optimization
		3 + background property optimization
		 */
		$this->settings['optimise_shorthands'] = 1;
		$this->settings['remove_last_;']       = true;
		/* rewrite all properties with low case, better for later gzip OK, safe*/
		$this->settings['case_properties'] = 1;

		/*
		 * sort properties in alpabetic order, better for later gzip
		 * but can cause trouble in case of overiding same propertie or using hack
		 */
		$this->settings['sort_properties'] = false;

		/*
		1, 3, 5, etc -- enable sorting selectors inside @media: a{}b{}c{}
		2, 5, 8, etc -- enable sorting selectors inside one CSS declaration: a,b,c{}
		preserve order by default cause it can break functionnality
		 */
		$this->settings['sort_selectors'] = 0;
		/* is dangeroues to be used: CSS is broken sometimes */
		$this->settings['merge_selectors'] = 0;
		/* preserve or not browser hacks */
		$this->settings['discard_invalid_selectors']  = false;
		$this->settings['discard_invalid_properties'] = false;
		$this->settings['css_level']                  = 'CSS2.1';
		$this->settings['preserve_css']               = false;
		$this->settings['timestamp']                  = false;
		$this->settings['template']                   = ''; // say that propertie exist.
		$this->set_cfg( 'template', 'default' ); // call load_template.
		/* Tells csstidy_optimise to keep leading zeros on decimal numbers, e.g., 0.7 */
		$this->settings['preserve_leading_zeros'] = false;
		$this->optimise                           = new csstidy_optimise( $this );

		$this->tokens_list = & $GLOBALS['csstidy']['tokens'];
	}

	/**
	 * Call the construct function.
	 */
	public function csstidy() {
		$this->__construct();
	}

	/**
	 * Get the value of a setting.
	 *
	 * @param string $setting - the settings.
	 * @access public
	 * @return mixed
	 * @version 1.0
	 */
	public function get_cfg( $setting ) {
		if ( isset( $this->settings[ $setting ] ) ) {
			return $this->settings[ $setting ];
		}
		return false;
	}

	/**
	 * Load a template
	 *
	 * @param string $template used by set_cfg to load a template via a configuration setting.
	 * @access private
	 * @version 1.4
	 */
	public function _load_template( $template ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
		switch ( $template ) {
			case 'default':
				$this->load_template( 'default' );
				break;

			case 'highest':
				$this->load_template( 'highest_compression' );
				break;

			case 'high':
				$this->load_template( 'high_compression' );
				break;

			case 'low':
				$this->load_template( 'low_compression' );
				break;

			default:
				$this->load_template( $template );
				break;
		}
	}

	/**
	 * Set the value of a setting.
	 *
	 * @param string $setting - the setting.
	 * @param mixed  $value - the value we're setting.
	 * @access public
	 * @return bool
	 * @version 1.0
	 */
	public function set_cfg( $setting, $value = null ) {
		if ( is_array( $setting ) && null === $value ) {
			foreach ( $setting as $setprop => $setval ) {
				$this->settings[ $setprop ] = $setval;
			}
			if ( array_key_exists( 'template', $setting ) ) {
				$this->_load_template( $this->settings['template'] );
			}
			return true;
		} elseif ( isset( $this->settings[ $setting ] ) && '' !== $value ) {
			$this->settings[ $setting ] = $value;
			if ( 'template' === $setting ) {
				$this->_load_template( $this->settings['template'] );
			}
			return true;
		}
		return false;
	}

	/**
	 * Adds a token to $this->tokens
	 *
	 * @param mixed  $type - the type.
	 * @param string $data - data.
	 * @param bool   $do add a token even if preserve_css is off.
	 * @access private
	 * @version 1.0
	 */
	public function _add_token( $type, $data, $do = false ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
		if ( $this->get_cfg( 'preserve_css' ) || $do ) {
			$this->tokens[] = array( $type, ( COMMENT === $type ) ? $data : trim( $data ) );
		}
	}

	/**
	 * Add a message to the message log
	 *
	 * @param string  $message - the message.
	 * @param string  $type - the type of message.
	 * @param integer $line - the line.
	 * @access private
	 * @version 1.0
	 */
	public function log( $message, $type, $line = -1 ) {
		if ( -1 === $line ) {
			$line = $this->line;
		}
		$line = (int) $line;
		$add  = array(
			'm' => $message,
			't' => $type,
		);
		if ( ! isset( $this->log[ $line ] ) || ! in_array( $add, $this->log[ $line ], true ) ) {
			$this->log[ $line ][] = $add;
		}
	}

	/**
	 * Parse unicode notations and find a replacement character
	 *
	 * @param string  $string - a string.
	 * @param integer $i - counting integer.
	 * @access private
	 * @return string
	 * @version 1.2
	 */
	public function _unicode( &$string, &$i ) { // phpcs:ignore PSR2.Methods.MethodDeclaration.Underscore
		++$i;
		$add      = '';
		$replaced = false;

		while ( $i < strlen( $string ) && ( ctype_xdigit( $string[ $i ] ) || ctype_space( $string[ $i ] ) ) && strlen( $add ) < 6 ) { // phpcs:ignore Squiz.PHP.DisallowSizeFunctionsInLoops.Found
			$add .= $string[ $i ];

			if ( ctype_space( $string[ $i ] ) ) {
				break;
			}
			++$i;
		}

		if ( hexdec( $add ) > 47 && hexdec( $add ) < 58 || hexdec( $add ) > 64 && hexdec( $add ) < 91 || hexdec( $add ) > 96 && hexdec( $add ) < 123 ) {
			$this->log( 'Replaced unicode notation: Changed \\' . $add . ' to ' . chr( hexdec( $add ) ), 'Information' );
			$add      = chr( hexdec( $add ) );
			$replaced = true;
		} else {
			$add = trim( '\\' . $add );
		}

		if ( @ctype_xdigit( $string[ $i + 1 ] ) && ctype_space( $string[ $i ] )
						&& ! $replaced || ! ctype_space( $string[ $i ] ) ) {
			--$i;
		}

		if ( '\\' !== $add || ! $this->get_cfg( 'remove_bslash' ) || strpos( $this->tokens_list, $string[ $i + 1 ] ) !== false ) {
			return $add;
		}

		if ( '\\' === $add ) {
			$this->log( 'Removed unnecessary backslash', 'Information' );
		}
		return '';
	}

	/**
	 * Write formatted output to a file
	 *
	 * @param string $filename - the file na,e.
	 * @param string $doctype when printing formatted, is a shorthand for the document type.
	 * @param bool   $externalcss when printing formatted, indicates whether styles to be attached internally or as an external stylesheet.
	 * @param string $title when printing formatted, is the title to be added in the head of the document.
	 * @param string $lang when printing formatted, gives a two-letter language code to be added to the output.
	 * @access public
	 * @version 1.4
	 */
	public function write_page( $filename, $doctype = 'xhtml1.1', $externalcss = true, $title = '', $lang = 'en' ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$this->write( $filename, true );
	}

	/**
	 * Write plain output to a file
	 *
	 * @param string $filename the file name.
	 * @param bool   $formatted whether to print formatted or not.
	 * @param string $doctype when printing formatted, is a shorthand for the document type.
	 * @param bool   $externalcss when printing formatted, indicates whether styles to be attached internally or as an external stylesheet.
	 * @param string $title when printing formatted, is the title to be added in the head of the document.
	 * @param string $lang when printing formatted, gives a two-letter language code to be added to the output.
	 * @param bool   $pre_code whether to add pre and code tags around the code (for light HTML formatted templates).
	 * @access public
	 * @version 1.4
	 */
	public function write( $filename, $formatted = false, $doctype = 'xhtml1.1', $externalcss = true, $title = '', $lang = 'en', $pre_code = true ) {
		$filename .= ( $formatted ) ? '.xhtml' : '.css';

		if ( ! is_dir( 'temp' ) ) {
			$madedir = mkdir( 'temp' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
			if ( ! $madedir ) {
				print 'Could not make directory "temp" in ' . __DIR__;
				exit;
			}
		}
		$handle = fopen( 'temp/' . $filename, 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( $handle ) {
			if ( ! $formatted ) {
				fwrite( $handle, $this->print->plain() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
			} else {
				fwrite( $handle, $this->print->formatted_page( $doctype, $externalcss, $title, $lang, $pre_code ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
			}
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
	}

	/**
	 * Loads a new template
	 *
	 * @param string $content either filename (if $from_file == true), content of a template file, "high_compression", "highest_compression", "low_compression", or "default".
	 * @param bool   $from_file uses $content as filename if true.
	 * @access public
	 * @version 1.1
	 * @see http://csstidy.sourceforge.net/templates.php
	 */
	public function load_template( $content, $from_file = true ) {
		$predefined_templates = & $GLOBALS['csstidy']['predefined_templates'];
		if ( 'high_compression' === $content || 'default' === $content || 'highest_compression' === $content || 'low_compression' === $content ) {
			$this->template = $predefined_templates[ $content ];
			return;
		}

		if ( $from_file ) {
			$content = strip_tags( file_get_contents( $content ), '<span>' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		}
		$content  = str_replace( "\r\n", "\n", $content ); // Unify newlines (because the output also only uses \n).
		$template = explode( '|', $content );

		$this->template = array_replace( $this->template, $template );
	}

	/**
	 * Starts parsing from URL
	 *
	 * @param string $url - the URL.
	 * @access public
	 * @version 1.0
	 */
	public function parse_from_url( $url ) {
		return $this->parse( @file_get_contents( $url ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	/**
	 * Checks if there is a token at the current position
	 *
	 * @param string  $string - the string we're checking.
	 * @param integer $i - an int.
	 * @access public
	 * @version 1.11
	 */
	public function is_token( &$string, $i ) {
		return ( strpos( $this->tokens_list, $string[ $i ] ) !== false && ! self::escaped( $string, $i ) );
	}

	/**
	 * Parses CSS in $string. The code is saved as array in $this->css
	 *
	 * @param string $string the CSS code.
	 * @access public
	 * @return bool
	 * @version 1.1
	 */
	public function parse( $string ) {
		// Temporarily set locale to en_US in order to handle floats properly.
		$old = @setlocale( LC_ALL, 0 );
		@setlocale( LC_ALL, 'C' );

		// PHP bug? Settings need to be refreshed in PHP4.
		$this->print = new csstidy_print( $this );

		$at_rules                 = & $GLOBALS['csstidy']['at_rules'];
		$quoted_string_properties = & $GLOBALS['csstidy']['quoted_string_properties'];

		$this->css              = array();
		$this->print->input_css = $string;
		$string                 = str_replace( "\r\n", "\n", $string ) . ' ';
		$cur_comment            = '';

		for ( $i = 0, $size = strlen( $string ); $i < $size; $i++ ) {
			if ( "\n" === $string[ $i ] || "\r" === $string[ $i ] ) {
				++$this->line;
			}

			switch ( $this->status ) {
				/* Case in at-block */
				case 'at':
					if ( self::is_token( $string, $i ) ) {
						if ( '/' === $string[ $i ] && '*' === @$string[ $i + 1 ] ) {
							$this->status = 'ic';
							++$i;
							$this->from[] = 'at';
						} elseif ( '{' === $string[ $i ] ) {
							$this->status = 'is';
							$this->at     = $this->css_new_media_section( $this->at );
							$this->_add_token( AT_START, $this->at );
						} elseif ( ',' === $string[ $i ] ) {
							$this->at = trim( $this->at ) . ',';
						} elseif ( '\\' === $string[ $i ] ) {
							$this->at .= $this->_unicode( $string, $i );
						} elseif ( in_array( $string[ $i ], array( '(', ')', ':', '.', '/' ), true ) ) {
							// fix for complicated media, i.e @media screen and (-webkit-min-device-pixel-ratio:1.5)
							// '/' is included for ratios in Opera: (-o-min-device-pixel-ratio: 3/2).
							$this->at .= $string[ $i ];
						}
					} else {
						$lastpos = strlen( $this->at ) - 1;
						if ( ! ( ( ctype_space( $this->at[ $lastpos ] ) || self::is_token( $this->at, $lastpos ) && ',' === $this->at[ $lastpos ] ) && ctype_space( $string[ $i ] ) ) ) {
							$this->at .= $string[ $i ];
						}
					}
					break;

				/* Case in-selector */
				case 'is':
					if ( self::is_token( $string, $i ) ) {
						if ( '/' === $string[ $i ] && '*' === @$string[ $i + 1 ] && '' === trim( $this->selector ) ) {
							$this->status = 'ic';
							++$i;
							$this->from[] = 'is';
						} elseif ( '@' === $string[ $i ] && '' === trim( $this->selector ) ) {
							// Check for at-rule.
							$this->invalid_at = true;
							foreach ( $at_rules as $name => $type ) {
								if ( ! strcasecmp( substr( $string, $i + 1, strlen( $name ) ), $name ) ) {
									( 'at' === $type ) ? $this->at = '@' . $name : $this->selector = '@' . $name;
									$this->status                  = $type;
									$i                            += strlen( $name );
									$this->invalid_at              = false;
								}
							}

							if ( $this->invalid_at ) {
								$this->selector  = '@';
								$invalid_at_name = '';
								for ( $j = $i + 1; $j < $size; ++$j ) {
									if ( ! ctype_alpha( $string[ $j ] ) ) {
										break;
									}
									$invalid_at_name .= $string[ $j ];
								}
								$this->log( 'Invalid @-rule: ' . $invalid_at_name . ' (removed)', 'Warning' );
							}
						} elseif ( ( '"' === $string[ $i ] || "'" === $string[ $i ] ) ) {
							$this->cur_string[] = $string[ $i ];
							$this->status       = 'instr';
							$this->str_char[]   = $string[ $i ];
							$this->from[]       = 'is';
							/* fixing CSS3 attribute selectors, i.e. a[href$=".mp3" */
							$this->quoted_string[] = ( '=' === $string[ $i - 1 ] );
						} elseif ( $this->invalid_at && ';' === $string[ $i ] ) {
							$this->invalid_at = false;
							$this->status     = 'is';
						} elseif ( '{' === $string[ $i ] ) {
							$this->status = 'ip';
							if ( '' === $this->at ) {
								$this->at = $this->css_new_media_section( DEFAULT_AT );
							}
							$this->selector = $this->css_new_selector( $this->at, $this->selector );
							$this->_add_token( SEL_START, $this->selector );
							$this->added = false;
						} elseif ( '}' === $string[ $i ] ) {
							$this->_add_token( AT_END, $this->at );
							$this->at           = '';
							$this->selector     = '';
							$this->sel_separate = array();
						} elseif ( ',' === $string[ $i ] ) {
							$this->selector       = trim( $this->selector ) . ',';
							$this->sel_separate[] = strlen( $this->selector );
						} elseif ( '\\' === $string[ $i ] ) {
							$this->selector .= $this->_unicode( $string, $i );
						} elseif ( '*' === $string[ $i ] && @in_array( $string[ $i + 1 ], array( '.', '#', '[', ':' ), true ) ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedElseif
							// remove unnecessary universal selector, FS#147.
						} else {
							$this->selector .= $string[ $i ];
						}
					} else {
						$lastpos = strlen( $this->selector ) - 1;
						if ( -1 === $lastpos || ! ( ( ctype_space( $this->selector[ $lastpos ] ) || self::is_token( $this->selector, $lastpos ) && ',' === $this->selector[ $lastpos ] ) && ctype_space( $string[ $i ] ) ) ) {
							$this->selector .= $string[ $i ];
						} elseif ( ctype_space( $string[ $i ] ) && $this->get_cfg( 'preserve_css' ) && ! $this->get_cfg( 'merge_selectors' ) ) {
							$this->selector .= $string[ $i ];
						}
					}
					break;

				/* Case in-property */
				case 'ip':
					if ( self::is_token( $string, $i ) ) {
						if ( ( ':' === $string[ $i ] || '=' === $string[ $i ] ) && '' !== $this->property ) {
							$this->status = 'iv';
							if ( ! $this->get_cfg( 'discard_invalid_properties' ) || self::property_is_valid( $this->property ) ) {
								$this->property = $this->css_new_property( $this->at, $this->selector, $this->property );
								$this->_add_token( PROPERTY, $this->property );
							}
						} elseif ( '/' === $string[ $i ] && '*' === @$string[ $i + 1 ] && '' === $this->property ) {
							$this->status = 'ic';
							++$i;
							$this->from[] = 'ip';
						} elseif ( '}' === $string[ $i ] ) {
							$this->explode_selectors();
							$this->status     = 'is';
							$this->invalid_at = false;
							$this->_add_token( SEL_END, $this->selector );
							$this->selector = '';
							$this->property = '';
						} elseif ( ';' === $string[ $i ] ) {
							$this->property = '';
						} elseif ( '\\' === $string[ $i ] ) {
							$this->property .= $this->_unicode( $string, $i );
						} elseif ( '' === $this->property && ! ctype_space( $string[ $i ] ) ) {
							// else this is dumb IE a hack, keep it.
							$this->property .= $string[ $i ];
						}
					} elseif ( ! ctype_space( $string[ $i ] ) ) {
						$this->property .= $string[ $i ];
					}
					break;

				/* Case in-value */
				case 'iv':
					$pn = ( ( "\n" === $string[ $i ] || "\r" === $string[ $i ] ) && $this->property_is_next( $string, $i + 1 ) || strlen( $string ) - 1 === $i );
					if ( ( self::is_token( $string, $i ) || $pn ) && ( ! ( ',' === $string[ $i ] && ! ctype_space( $string[ $i + 1 ] ) ) ) ) {
						if ( '/' === $string[ $i ] && '*' === @$string[ $i + 1 ] ) {
							$this->status = 'ic';
							++$i;
							$this->from[] = 'iv';
						} elseif ( ( '"' === $string[ $i ] || "'" === $string[ $i ] || '(' === $string[ $i ] ) ) {
							$this->cur_string[]    = $string[ $i ];
							$this->str_char[]      = ( '(' === $string[ $i ] ) ? ')' : $string[ $i ];
							$this->status          = 'instr';
							$this->from[]          = 'iv';
							$this->quoted_string[] = in_array( strtolower( $this->property ), $quoted_string_properties, true );
						} elseif ( ',' === $string[ $i ] ) {
							$this->sub_value = trim( $this->sub_value ) . ',';
						} elseif ( '\\' === $string[ $i ] ) {
							$this->sub_value .= $this->_unicode( $string, $i );
						} elseif ( ';' === $string[ $i ] || $pn ) {
							if ( '@' === $this->selector[0] && isset( $at_rules[ substr( $this->selector, 1 ) ] ) && 'iv' === $at_rules[ substr( $this->selector, 1 ) ] ) {
								$this->status = 'is';

								switch ( $this->selector ) {
									case '@charset':
										/* Add quotes to charset */
										$this->sub_value_arr[] = '"' . trim( $this->sub_value ) . '"';
										$this->charset         = $this->sub_value_arr[0];
										break;
									case '@namespace':
										/* Add quotes to namespace */
										$this->sub_value_arr[] = '"' . trim( $this->sub_value ) . '"';
										$this->namespace       = implode( ' ', $this->sub_value_arr );
										break;
									case '@import':
										$this->sub_value = trim( $this->sub_value );

										if ( empty( $this->sub_value_arr ) ) {
											// Quote URLs in imports only if they're not already inside url() and not already quoted.
											if ( substr( $this->sub_value, 0, 4 ) !== 'url(' ) {
												if ( ! ( substr( $this->sub_value, -1 ) === $this->sub_value[0] && in_array( $this->sub_value[0], array( "'", '"' ), true ) ) ) {
													$this->sub_value = '"' . $this->sub_value . '"';
												}
											}
										}

										$this->sub_value_arr[] = $this->sub_value;
										$this->import[]        = implode( ' ', $this->sub_value_arr );
										break;
								}

								$this->sub_value_arr = array();
								$this->sub_value     = '';
								$this->selector      = '';
								$this->sel_separate  = array();
							} else {
								$this->status = 'ip';
							}
						} elseif ( '}' !== $string[ $i ] ) {
							$this->sub_value .= $string[ $i ];
						}
						if ( ( '}' === $string[ $i ] || ';' === $string[ $i ] || $pn ) && ! empty( $this->selector ) ) {
							if ( '' === $this->at ) {
								$this->at = $this->css_new_media_section( DEFAULT_AT );
							}

							// case settings.
							if ( $this->get_cfg( 'lowercase_s' ) ) {
								$this->selector = strtolower( $this->selector );
							}
							$this->property = strtolower( $this->property );

							$this->optimise->subvalue();
							if ( '' !== $this->sub_value ) {
								if ( substr( $this->sub_value, 0, 6 ) === 'format' ) {
									$format_strings = self::parse_string_list( substr( $this->sub_value, 7, -1 ) );
									if ( ! $format_strings ) {
										$this->sub_value = '';
									} else {
										$this->sub_value = 'format(';

										foreach ( $format_strings as $format_string ) {
											$this->sub_value .= '"' . str_replace( '"', '\\"', $format_string ) . '",';
										}

										$this->sub_value = substr( $this->sub_value, 0, -1 ) . ')';
									}
								}
								if ( '' !== $this->sub_value ) {
									$this->sub_value_arr[] = $this->sub_value;
								}
								$this->sub_value = '';
							}

							$this->value = array_shift( $this->sub_value_arr );
							while ( $this->sub_value_arr ) {
								$this->value .= ' ' . array_shift( $this->sub_value_arr );
							}

							$this->optimise->value();

							$valid = self::property_is_valid( $this->property );
							if ( ( ! $this->invalid_at || $this->get_cfg( 'preserve_css' ) ) && ( ! $this->get_cfg( 'discard_invalid_properties' ) || $valid ) ) {
								$this->css_add_property( $this->at, $this->selector, $this->property, $this->value );
								$this->_add_token( VALUE, $this->value );
								$this->optimise->shorthands();
							}
							if ( ! $valid ) {
								if ( $this->get_cfg( 'discard_invalid_properties' ) ) {
									$this->log( 'Removed invalid property: ' . $this->property, 'Warning' );
								} else {
									$this->log( 'Invalid property in ' . strtoupper( $this->get_cfg( 'css_level' ) ) . ': ' . $this->property, 'Warning' );
								}
							}

							$this->property      = '';
							$this->sub_value_arr = array();
							$this->value         = '';
						}
						if ( '}' === $string[ $i ] ) {
							$this->explode_selectors();
							$this->_add_token( SEL_END, $this->selector );
							$this->status     = 'is';
							$this->invalid_at = false;
							$this->selector   = '';
						}
					} elseif ( ! $pn ) {
						$this->sub_value .= $string[ $i ];

						if ( ctype_space( $string[ $i ] ) || ',' === $string[ $i ] ) {
							$this->optimise->subvalue();
							if ( '' !== $this->sub_value ) {
								$this->sub_value_arr[] = $this->sub_value;
								$this->sub_value       = '';
							}
						}
					}
					break;

				/* Case in string */
				case 'instr':
					$_str_char   = $this->str_char[ count( $this->str_char ) - 1 ];
					$_cur_string = $this->cur_string[ count( $this->cur_string ) - 1 ];
					$temp_add    = $string[ $i ];

					// Add another string to the stack. Strings can't be nested inside of quotes, only parentheses, but
					// parentheticals can be nested more than once.
					if ( ')' === $_str_char && ( '(' === $string[ $i ] || '"' === $string[ $i ] || '\'' === $string[ $i ] ) && ! self::escaped( $string, $i ) ) {
						$this->cur_string[]    = $string[ $i ];
						$this->str_char[]      = $string[ $i ] === '(' ? ')' : $string[ $i ];
						$this->from[]          = 'instr';
						$this->quoted_string[] = ! ( '(' === $string[ $i ] );
						continue 2;
					}

					if ( ')' !== $_str_char && ( "\n" === $string[ $i ] || "\r" === $string[ $i ] ) && ! ( '\\' === $string[ $i - 1 ] && ! self::escaped( $string, $i - 1 ) ) ) {
						$temp_add = '\\A';
						$this->log( 'Fixed incorrect newline in string', 'Warning' );
					}

					$_cur_string .= $temp_add;

					if ( $string[ $i ] === $_str_char && ! self::escaped( $string, $i ) ) {
						$_quoted_string = array_pop( $this->quoted_string );

						$this->status = array_pop( $this->from );

						if ( ! preg_match( '|[' . implode( '', $GLOBALS['csstidy']['whitespace'] ) . ']|uis', $_cur_string ) && 'content' !== $this->property ) {
							if ( ! $_quoted_string ) {
								if ( ')' !== $_str_char ) {
									// Convert properties like
									// font-family: 'Arial';
									// to
									// font-family: Arial;
									// or
									// url("abc")
									// to
									// url(abc).
									$_cur_string = substr( $_cur_string, 1, -1 );
								}
							} else {
								$_quoted_string = false;
							}
						}

						array_pop( $this->cur_string );
						array_pop( $this->str_char );

						if ( ')' === $_str_char ) {
							$_cur_string = '(' . trim( substr( $_cur_string, 1, -1 ) ) . ')';
						}

						if ( 'iv' === $this->status ) {
							// phpcs:disable Squiz.PHP.CommentedOutCode.Found, Squiz.Commenting.BlockComment.NoNewLine
							// WPCOM hack: prevents CSSTidy from removing spaces after commas inside
							// declaration's values.
							// For more information, see D74626-code.
							/*if ( ! $_quoted_string ) {
								if ( strpos( $_cur_string, ',' ) !== false ) {
									// we can on only remove space next to ','.
									$_cur_string = implode( ',', array_map( 'trim', explode( ',', $_cur_string ) ) );
								}
								// and multiple spaces (too expensive).
								if ( strpos( $_cur_string, '  ' ) !== false ) {
									$_cur_string = preg_replace( ',\s+,', ' ', $_cur_string );
								}
							}*/
							// phpcs:enable Squiz.PHP.CommentedOutCode.Found, Squiz.Commenting.BlockComment.NoNewLine
							$this->sub_value .= $_cur_string;
						} elseif ( 'is' === $this->status ) {
							$this->selector .= $_cur_string;
						} elseif ( 'instr' === $this->status ) {
							$this->cur_string[ count( $this->cur_string ) - 1 ] .= $_cur_string;
						}
					} else {
						$this->cur_string[ count( $this->cur_string ) - 1 ] = $_cur_string;
					}
					break;

				/* Case in-comment */
				case 'ic':
					if ( '*' === $string[ $i ] && '/' === $string[ $i + 1 ] ) {
						$this->status = array_pop( $this->from );
						++$i;
						$this->_add_token( COMMENT, $cur_comment );
						$cur_comment = '';
					} else {
						$cur_comment .= $string[ $i ];
					}
					break;
			}
		}

		$this->optimise->postparse();

		$this->print->_reset();

		@setlocale( LC_ALL, $old ); // Set locale back to original setting.

		return ! ( empty( $this->css ) && empty( $this->import ) && empty( $this->charset ) && empty( $this->tokens ) && empty( $this->namespace ) );
	}

	/**
	 * Explodes selectors
	 *
	 * @access private
	 * @version 1.0
	 */
	public function explode_selectors() {
		// Explode multiple selectors.
		if ( $this->get_cfg( 'merge_selectors' ) === 1 ) {
			$new_sels             = array();
			$lastpos              = 0;
			$this->sel_separate[] = strlen( $this->selector );
			foreach ( $this->sel_separate as $num => $pos ) {
				if ( count( $this->sel_separate ) - 1 === $num ) {
					++$pos;
				}

				$new_sels[] = substr( $this->selector, $lastpos, $pos - $lastpos - 1 );
				$lastpos    = $pos;
			}

			if ( count( $new_sels ) > 1 ) {
				foreach ( $new_sels as $selector ) {
					if ( isset( $this->css[ $this->at ][ $this->selector ] ) ) {
						$this->merge_css_blocks( $this->at, $selector, $this->css[ $this->at ][ $this->selector ] );
					}
				}
				unset( $this->css[ $this->at ][ $this->selector ] );
			}
		}
		$this->sel_separate = array();
	}

	/**
	 * Checks if a character is escaped (and returns true if it is)
	 *
	 * @param string  $string - the string.
	 * @param integer $pos - the position.
	 * @access public
	 * @return bool
	 * @version 1.02
	 */
	public static function escaped( &$string, $pos ) {
		return ! ( @( '\\' !== $string[ $pos - 1 ] ) || self::escaped( $string, $pos - 1 ) );
	}

	/**
	 * Adds a property with value to the existing CSS code
	 *
	 * @param string $media - the media.
	 * @param string $selector - the selector.
	 * @param string $property - the property.
	 * @param string $new_val - new value.
	 * @access private
	 * @version 1.2
	 */
	public function css_add_property( $media, $selector, $property, $new_val ) {
		if ( $this->get_cfg( 'preserve_css' ) || '' === trim( $new_val ) ) {
			return;
		}

		$this->added = true;
		if ( isset( $this->css[ $media ][ $selector ][ $property ] ) ) {
			if ( ( self::is_important( $this->css[ $media ][ $selector ][ $property ] ) && self::is_important( $new_val ) ) || ! self::is_important( $this->css[ $media ][ $selector ][ $property ] ) ) {
				$this->css[ $media ][ $selector ][ $property ] = trim( $new_val );
			}
		} else {
			$this->css[ $media ][ $selector ][ $property ] = trim( $new_val );
		}
	}

	/**
	 * Start a new media section.
	 * Check if the media is not already known,
	 * else rename it with extra spaces
	 * to avoid merging
	 *
	 * @param string $media - the media.
	 * @return string
	 */
	public function css_new_media_section( $media ) {
		if ( $this->get_cfg( 'preserve_css' ) ) {
			return $media;
		}

		// if the last @media is the same as this keep it.
		if ( ! $this->css || ! is_array( $this->css ) || empty( $this->css ) ) {
			return $media;
		}
		end( $this->css );
		$at = current( $this->css );
		if ( $at === $media ) {
			return $media;
		}
		while ( isset( $this->css[ $media ] ) ) {
			if ( is_numeric( $media ) ) {
				++$media;
			} else {
				$media .= ' ';
			}
		}
		return $media;
	}

	/**
	 * Start a new selector.
	 * If already referenced in this media section,
	 * rename it with extra space to avoid merging
	 * except if merging is required,
	 * or last selector is the same (merge siblings)
	 *
	 * Never merge @font-face
	 *
	 * @param string $media - the media.
	 * @param string $selector - the selector.
	 * @return string
	 */
	public function css_new_selector( $media, $selector ) {
		if ( $this->get_cfg( 'preserve_css' ) ) {
			return $selector;
		}
		$selector = trim( $selector );
		if ( strncmp( $selector, '@font-face', 10 ) !== 0 ) {
			if ( $this->settings['merge_selectors'] ) {
				return $selector;
			}

			if ( ! $this->css || ! isset( $this->css[ $media ] ) || ! $this->css[ $media ] ) {
				return $selector;
			}

			// if last is the same, keep it.
			end( $this->css[ $media ] );
			$sel = current( $this->css[ $media ] );
			if ( $sel === $selector ) {
				return $selector;
			}
		}

		while ( isset( $this->css[ $media ][ $selector ] ) ) {
			$selector .= ' ';
		}
		return $selector;
	}

	/**
	 * Start a new propertie.
	 * If already references in this selector,
	 * rename it with extra space to avoid override
	 *
	 * @param string $media - the media.
	 * @param string $selector - the selector.
	 * @param string $property - the property.
	 * @return string
	 */
	public function css_new_property( $media, $selector, $property ) {
		if ( $this->get_cfg( 'preserve_css' ) ) {
			return $property;
		}
		if ( ! $this->css || ! isset( $this->css[ $media ][ $selector ] ) || ! $this->css[ $media ][ $selector ] ) {
			return $property;
		}

		while ( isset( $this->css[ $media ][ $selector ][ $property ] ) ) {
			$property .= ' ';
		}

		return $property;
	}

	/**
	 * Adds CSS to an existing media/selector
	 *
	 * @param string $media - the media.
	 * @param string $selector - the selector.
	 * @param array  $css_add - css being added.
	 * @access private
	 * @version 1.1
	 */
	public function merge_css_blocks( $media, $selector, $css_add ) {
		foreach ( $css_add as $property => $value ) {
			$this->css_add_property( $media, $selector, $property, $value, false );
		}
	}

	/**
	 * Checks if $value is !important.
	 *
	 * @param string $value - the value.
	 * @return bool
	 * @access public
	 * @version 1.0
	 */
	public static function is_important( &$value ) {
		return ( ! strcasecmp( substr( str_replace( $GLOBALS['csstidy']['whitespace'], '', $value ), -10, 10 ), '!important' ) );
	}

	/**
	 * Returns a value without !important
	 *
	 * @param string $value - the value.
	 * @return string
	 * @access public
	 * @version 1.0
	 */
	public static function gvw_important( $value ) {
		if ( self::is_important( $value ) ) {
			$value = trim( $value );
			$value = substr( $value, 0, -9 );
			$value = trim( $value );
			$value = substr( $value, 0, -1 );
			$value = trim( $value );
			return $value;
		}
		return $value;
	}

	/**
	 * Checks if the next word in a string from pos is a CSS property
	 *
	 * @param string  $istring - if it's a string.
	 * @param integer $pos - position.
	 * @return bool
	 * @access private
	 * @version 1.2
	 */
	public function property_is_next( $istring, $pos ) {
		$all_properties = & $GLOBALS['csstidy']['all_properties'];
		$istring        = substr( $istring, $pos, strlen( $istring ) - $pos );
		$pos            = strpos( $istring, ':' );
		if ( false === $pos ) {
			return false;
		}
		$istring = strtolower( trim( substr( $istring, 0, $pos ) ) );
		if ( isset( $all_properties[ $istring ] ) ) {
			$this->log( 'Added semicolon to the end of declaration', 'Warning' );
			return true;
		}
		return false;
	}

	/**
	 * Checks if a property is valid
	 *
	 * @param string $property - the property.
	 * @return bool;
	 * @access public
	 * @version 1.0
	 */
	public function property_is_valid( $property ) {
		$property = strtolower( $property );
		if ( in_array( trim( $property ), $GLOBALS['csstidy']['multiple_properties'], true ) ) {
			$property = trim( $property );
		}
		$all_properties = & $GLOBALS['csstidy']['all_properties'];
		return ( isset( $all_properties[ $property ] ) && strpos( $all_properties[ $property ], strtoupper( $this->get_cfg( 'css_level' ) ) ) !== false );
	}

	/**
	 * Accepts a list of strings (e.g., the argument to format() in a @font-face src property)
	 * and returns a list of the strings.  Converts things like:
	 *
	 * Format(abc) => format("abc")
	 * format(abc def) => format("abc","def")
	 * format(abc "def") => format("abc","def")
	 * format(abc, def, ghi) => format("abc","def","ghi")
	 * format("abc",'def') => format("abc","def")
	 * format("abc, def, ghi") => format("abc, def, ghi")
	 *
	 * @param string $value - the value.
	 * @return array
	 */
	public function parse_string_list( $value ) {
		$value = trim( $value );

		// Case: if it's empty.
		if ( ! $value ) {
			return array();
		}

		$strings = array();

		$in_str         = false;
		$current_string = '';

		for ( $i = 0, $_len = strlen( $value ); $i < $_len; $i++ ) {
			if ( ( ',' === $value[ $i ] || ' ' === $value[ $i ] ) && true === $in_str ) {
				$in_str         = false;
				$strings[]      = $current_string;
				$current_string = '';
			} elseif ( '"' === $value[ $i ] || "'" === $value[ $i ] ) {
				if ( $in_str === $value[ $i ] ) {
					$strings[]      = $current_string;
					$in_str         = false;
					$current_string = '';
					continue;
				} elseif ( ! $in_str ) {
					$in_str = $value[ $i ];
				}
			} elseif ( $in_str ) {
				$current_string .= $value[ $i ];
			} elseif ( ! preg_match( '/[\s,]/', $value[ $i ] ) ) {
				$in_str         = true;
				$current_string = $value[ $i ];
			}
		}

		if ( $current_string ) {
			$strings[] = $current_string;
		}

		return $strings;
	}
}
