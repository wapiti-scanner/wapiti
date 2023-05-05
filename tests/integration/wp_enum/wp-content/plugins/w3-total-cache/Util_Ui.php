<?php
namespace W3TC;

use DOMDocument;

class Util_Ui {
	/**
	 * Returns button html
	 *
	 * @param string $text
	 * @param string $onclick
	 * @param string $class
	 * @return string
	 */
	public static function button( $text, $onclick = '', $class = 'button',
		$name = '' ) {
		$maybe_name = ( empty( $name ) ? '' : ' name="' . esc_attr( $name ) . '"' );
		return '<input type="button"' . $maybe_name . ' class="' .
			esc_attr( $class ) . '" value="' . esc_attr( $text ) .
			'" onclick="' . esc_attr( $onclick ) . '" />';
	}

	/**
	 * Returns button link html.
	 *
	 * @param string $text       Text.
	 * @param string $url        URL.
	 * @param bool   $new_window Open link in a new window.
	 * @param string $class      Class.
	 * @param string $name       Name.
	 * @return string
	 */
	public static function button_link( $text, $url, $new_window = false, $class = 'button', $name = '' ) {
		$url = str_replace( '&amp;', '&', $url );

		if ( $new_window ) {
			$onclick = sprintf( 'window.open(\'%s\');', addslashes( $url ) );
		} else {
			$onclick = '';

			if ( strpos( $class, 'w3tc-button-ignore-change' ) >= 0 ) {
				$onclick .= 'w3tc_beforeupload_unbind(); ';
			}

			$onclick .= sprintf( 'document.location.href=\'%s\';', addslashes( $url ) );
		}

		return self::button( $text, $onclick, $class, $name );
	}

	public static function url( $addon ) {
		if ( ! isset( $addon['page'] ) ) {
			$addon['page'] = Util_Request::get_string( 'page', 'w3tc_dashboard' );
		}

		$url = 'admin.php';
		$amp = '?';
		foreach ( $addon as $key => $value ) {
			$url .= $amp . rawurlencode( $key ) . '=' . rawurlencode( $value );
			$amp = '&';
		}

		$url = wp_nonce_url( $url, 'w3tc' );

		return $url;
	}

	/**
	 * Returns hide note button html
	 *
	 * @param string  $text
	 * @param string  $note
	 * @param string  $redirect
	 * @param boolean $admin         if to use config admin.
	 * @param string  $page
	 * @param string  $custom_method
	 * @return string
	 */
	public static function button_hide_note( $text, $note, $redirect = '',
		$admin = false, $page = '',
		$custom_method = 'w3tc_default_hide_note' ) {
		if ( '' === $page ) {
			$page = Util_Request::get_string( 'page', 'w3tc_dashboard' );
		}

		$url = sprintf( 'admin.php?page=%s&%s&note=%s', $page, $custom_method, $note );

		if ( $admin ) {
			$url .= '&admin=1';
		}

		if ( '' !== $redirect ) {
			$url .= '&redirect=' . rawurlencode( $redirect );
		}

		$url = wp_nonce_url( $url, 'w3tc' );

		return self::button_link( $text, $url, false, 'button', 'w3tc_hide_' . $custom_method );
	}

	public static function button_hide_note2( $parameters ) {
		return self::button_link(
			__( 'Hide this message', 'w3-total-cache' ),
			self::url( $parameters ),
			false,
			'button',
			'w3tc_hide_' . self::config_key_to_http_name( $parameters['key'] )
		);
	}

	public static function action_button( $action, $url, $class = '',
		$new_window = false ) {
		return self::button_link( $action, $url, $new_window, $class );
	}
	/**
	 * Returns popup button html
	 *
	 * @param string  $text
	 * @param string  $action
	 * @param string  $params
	 * @param integer $width
	 * @param integer $height
	 * @return string
	 */
	public static function button_popup( $text, $action, $params = '', $width = 800, $height = 600 ) {
		$url = wp_nonce_url( sprintf( 'admin.php?page=w3tc_dashboard&w3tc_%s%s', $action, ( '' !== $params ? '&' . $params : '' ) ), 'w3tc' );
		$url = str_replace( '&amp;', '&', $url );

		$onclick = sprintf( 'window.open(\'%s\', \'%s\', \'width=%d,height=%d,status=no,toolbar=no,menubar=no,scrollbars=yes\');', $url, $action, $width, $height );

		return self::button( $text, $onclick );
	}

	/**
	 * Returns label string for a config key.
	 *
	 * @param string $config_key
	 * @param string $area
	 */
	public static function config_label( $config_key ) {
		static $config_labels = null;
		if ( is_null( $config_labels ) ) {
			$config_labels = apply_filters( 'w3tc_config_labels', array() );
		}

		if ( isset( $config_labels[ $config_key ] ) ) {
			return $config_labels[ $config_key ];
		}

		return '';
	}

	/**
	 * Prints the label string for a config key.
	 *
	 * @param string $config_key
	 * @param string $area
	 */
	public static function e_config_label( $config_key ) {
		$config_label = self::config_label( $config_key );
		echo wp_kses(
			$config_label,
			self::get_allowed_html_for_wp_kses_from_content( $config_label )
		);
	}

	/**
	 * Returns postbox header
	 *
	 * WordPress 5.5 introduced .postbox-header, which broke the styles of our postboxes. This was
	 * resolved by adding additional css to /pub/css/options.css and pub/css/widget.css tagged with
	 * a "WP 5.5" comment.
	 *
	 * @todo Add .postbox-header to our postboxes and cleanup css.
	 * @link https://github.com/BoldGrid/w3-total-cache/issues/237
	 *
	 * @param string $title
	 * @param string $class
	 * @param string $id
	 * @return void
	 */
	public static function postbox_header( $title, $class = '', $id = '' ) {
		if ( ! empty( $id ) ) {
			$id = ' id="' . esc_attr( $id ) . '"';
		}
		echo '<div' . $id . ' class="postbox ' . esc_attr( $class ) . '">
		<div class="handlediv" title="' . esc_attr__( 'Click to toggle', 'w3-total-cache' ) . '"><br /></div>
		<h3 class="hndle"><span>' . wp_kses( $title, self::get_allowed_html_for_wp_kses_from_content( $title ) ) . '</span></h3>
		<div class="inside">';
	}

	/**
	 * Returns postbox footer
	 *
	 * @return void
	 */
	public static function postbox_footer() {
		echo '</div></div>';
	}

	public static function button_config_save( $id = '', $extra = '' ) {
		$b1_id = 'w3tc_save_options_' . $id;
		$b2_id = 'w3tc_default_save_and_flush_' . $id;

		?>
		<p class="submit">
			<?php
			$nonce_field = self::nonce_field( 'w3tc' );
			echo wp_kses(
				$nonce_field,
				self::get_allowed_html_for_wp_kses_from_content( $nonce_field )
			);
			?>
			<input type="submit" id="<?php echo esc_attr( $b1_id ); ?>"
				name="w3tc_save_options"
				class="w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Save all settings', 'w3-total-cache' ); ?>" />
			<?php
			echo wp_kses(
				$extra,
				self::get_allowed_html_for_wp_kses_from_content( $extra )
			);
			?>
			<?php if ( ! is_network_admin() ) : ?>
			<input type="submit" id="<?php echo esc_attr( $b2_id ); ?>"
				name="w3tc_default_save_and_flush" style="float: right"
				class="w3tc-button-save button-primary"
				value="<?php esc_attr_e( 'Save Settings & Purge Caches', 'w3-total-cache' ); ?>" />
			<?php endif ?>
		</p>
		<?php
	}

	public static function sealing_disabled( $key ) {
		$c = Dispatcher::config();
		if ( $c->is_sealed( $key ) ) {
			echo 'disabled="disabled" ';
		}
	}

	/**
	 * Returns nonce field HTML
	 *
	 * @param string $action
	 * @param string $name
	 * @param bool   $referer
	 * @internal param bool $echo
	 * @return string
	 */
	public static function nonce_field( $action = -1, $name = '_wpnonce', $referer = true ) {
		$return = '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( wp_create_nonce( $action ) ) . '" />';

		if ( $referer ) {
			$return .= wp_referer_field( false );
		}

		return $return;
	}

	/**
	 * Returns an notification box
	 *
	 * @param string $message
	 * @param string $id      adds an id to the notification box.
	 * @return string
	 */
	public static function get_notification_box( $message, $id = '' ) {
		$page_val = Util_Request::get_string( 'page' );

		if ( empty( $page_val ) || ( ! empty( $page_val ) && 'w3tc_' !== substr( $page_val, 0, 5 ) ) ) {
			$logo = sprintf(
				'<img src="%s" alt="W3 Total Cache" style="height:30px" />"',
				esc_url( plugins_url( '/pub/img/W3TC_dashboard_logo_title.png', W3TC_FILE ) ) . ''
			);
		} else {
			$logo = '';
		}
		return sprintf(
			'<div %s class="updated">%s</div>',
			$id ? 'id="' . esc_attr( $id ) . '"' : '',
			$logo . wp_kses( $message, self::get_allowed_html_for_wp_kses_from_content( $message ) )
		);
	}

	/**
	 * Echos an notification box
	 *
	 * @param string $message
	 * @param string $id      adds an id to the notification box.
	 */
	public static function e_notification_box( $message, $id = '' ) {
		$notification_box = self::get_notification_box( $message, $id );
		echo wp_kses(
			$notification_box,
			self::get_allowed_html_for_wp_kses_from_content( $notification_box )
		);
	}

	/**
	 * Echos an error box.
	 *
	 * @param string $message Message.
	 * @param string $id      Id.
	 */
	public static function error_box( $message, $id = '' ) {
		$page_val = Util_Request::get_string( 'page' );

		if ( empty( $page_val ) || ( ! empty( $page_val ) && 'w3tc_' !== substr( $page_val, 0, 5 ) ) ) {
			$logo = sprintf(
				'<img src="%s" alt="W3 Total Cache" style="height:30px" />',
				esc_url( plugins_url( '/pub/img/W3TC_dashboard_logo_title.png', W3TC_FILE ) . '' )
			);
		} else {
			$logo = '';
		}

		$v = sprintf(
			'<div %s class="error">%s</div>',
			$id ? 'id="' . esc_attr( $id ) . '"' : '',
			$logo . wp_kses( $message, self::get_allowed_html_for_wp_kses_from_content( $message ) )
		);

		echo wp_kses(
			$v,
			self::get_allowed_html_for_wp_kses_from_content( $v )
		);
	}

	/**
	 * Format bytes into B, KB, MB, GB and TB
	 *
	 * @param unknown $bytes
	 * @param int     $precision
	 * @return string
	 */
	public static function format_bytes( $bytes, $precision = 2 ) {
		$units = array( 'B', 'KB', 'MB', 'GB', 'TB' );

		$bytes = max( $bytes, 0 );
		$pow   = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
		$pow   = min( $pow, count( $units ) - 1 );

		// Uncomment one of the following alternatives.
		$bytes /= pow( 1024, $pow );
		// $bytes /= ( 1 << ( 10 * $pow ) );

		return round( $bytes, $precision ) . ' ' . $units[ $pow ];
	}

	public static function format_mbytes( $bytes, $precision = 2 ) {
		$units = array( 'B', 'KB', 'MB', 'GB', 'TB' );

		$bytes = max( $bytes, 0 );
		$pow   = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
		$pow   = min( $pow, count( $units ) - 1 );

		// Uncomment one of the following alternatives.
		$bytes /= pow( 1024, $pow );
		// $bytes /= ( 1 << ( 10 * $pow ) );

		return round( $bytes, $precision ) . ' ' . $units[ $pow + 2 ];
	}

	/**
	 * Returns an input text element
	 *
	 * @param string $id
	 * @param string $name
	 * @param string $value
	 * @param bool   $disabled
	 * @param int    $size
	 */
	public static function r_hidden( $id, $name, $value ) {
		return '<input type="hidden" id="' . esc_attr( $id ) .
			'" name="' . esc_attr( $name ) .
			'" value="' . esc_attr( $value ) . '" />';
	}

	/**
	 * Echos an input text element
	 *
	 * @param string $id
	 * @param string $name
	 * @param string $value
	 * @param bool   $disabled
	 * @param int    $size
	 */
	public static function hidden( $id, $name, $value ) {
		$hidden = self::r_hidden( $id, $name, $value );
		echo wp_kses(
			$hidden,
			self::get_allowed_html_for_wp_kses_from_content( $hidden )
		);
	}

	/**
	 * Echos an label element
	 *
	 * @param string $id
	 * @param string $text
	 */
	public static function label( $id, $text ) {
		$label = '<label for="' . esc_attr( $id ) . '">' . $text . '</label>';
		echo wp_kses(
			$label,
			self::get_allowed_html_for_wp_kses_from_content( $label )
		);
	}

	/**
	 * Echos an input text element
	 *
	 * @param string $id
	 * @param string $name
	 * @param string $value
	 * @param bool   $disabled
	 * @param int    $size
	 */
	public static function textbox( $id, $name, $value, $disabled = false,
			$size = 40, $type = 'text', $placeholder = '' ) {
		echo '<input class="enabled" type="' . esc_attr( $type ) . '"
			 id="' . esc_attr( $id ) . '"
			 name="' . esc_attr( $name ) . '"
			 value="' . esc_attr( $value ) . '" ';
		disabled( $disabled );
		echo ' size="' . esc_attr( $size ) . '"';

		if ( ! empty( $placeholder ) ) {
			echo ' placeholder="' . esc_attr( $placeholder ) . '"';
		}

		echo ' />';
	}

	/**
	 * Echos an input password element
	 *
	 * @param string $id
	 * @param string $name
	 * @param string $value
	 * @param bool   $disabled
	 * @param int    $size
	 */
	public static function passwordbox( $id, $name, $value, $disabled = false, $size = 40 ) {
		echo '<input class="enabled" type="password"
			 id="' . esc_attr( $id ) . '"
			 name="' . esc_attr( $name ) . '"
			 value="' . esc_attr( $value ) . '" ';
		disabled( $disabled );
		echo ' size="' . esc_attr( $size ) . '" />';
	}

	/**
	 * Echos an select element
	 *
	 * @param string $id
	 * @param string $name
	 * @param bool   $state     whether checked or not.
	 * @param bool   $disabled
	 * @param array  $optgroups
	 */
	public static function selectbox( $id, $name, $value, $values,
			$disabled = false, $optgroups = null ) {
		echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" ';
		disabled( $disabled );
		echo ">\n";

		if ( ! is_array( $optgroups ) ) {
			// simle control.
			foreach ( $values as $key => $descriptor ) {
				self::option( $key, $value, $descriptor );
			}
		} else {
			// with optgroups.
			$current_optgroup = -1;
			foreach ( $values as $key => $descriptor ) {
				$optgroup = ( isset( $descriptor['optgroup'] ) ? $descriptor['optgroup'] : -1 );
				if ( $optgroup !== $current_optgroup ) {
					if ( -1 !== $current_optgroup ) {
						echo '</optgroup>';
					}
					echo '<optgroup label="' . esc_attr( $optgroups[ $optgroup ] ) . '">' . "\n";
					$current_optgroup = $optgroup;
				}

				self::option( $key, $value, $descriptor );
			}

			if ( -1 !== $current_optgroup ) {
				echo '</optgroup>';
			}
		}

		echo '</select>';
	}

	private static function option( $key, $selected_value, $descriptor ) {
		if ( ! is_array( $descriptor ) ) {
			$label    = $descriptor;
			$disabled = false;
		} else {
			$label    = $descriptor['label'];
			$disabled = ! empty( $descriptor['disabled'] );
		}

		echo '<option value="' . esc_attr( $key ) . '" ';
		selected( $selected_value, $key );
		disabled( $disabled );
		echo '>' . wp_kses( $label, self::get_allowed_html_for_wp_kses_from_content( $label ) ) . '</option>' . "\n";
	}

	/**
	 * Echos a group of radio elements
	 * values: value => label pair or
	 * value => array(label, disabled, postfix).
	 */
	public static function radiogroup( $name, $value, $values,
			$disabled = false, $separator = '' ) {
		$first = true;
		foreach ( $values as $key => $label_or_array ) {
			if ( $first ) {
				$first = false;
			} else {
				echo wp_kses(
					$separator,
					self::get_allowed_html_for_wp_kses_from_content( $separator )
				);
			}

			$label         = '';
			$item_disabled = false;
			$postfix       = '';
			$pro_feature   = false;

			if ( ! is_array( $label_or_array ) ) {
				$label = $label_or_array;
			} else {
				$label         = $label_or_array['label'];
				$item_disabled = $label_or_array['disabled'];
				$postfix       = isset( $label_or_array['postfix'] ) ? $label_or_array['postfix'] : '';
				$pro_feature   = isset( $label_or_array['pro_feature'] ) ? $label_or_array['pro_feature'] : false;
			}

			if ( $pro_feature ) {
				self::pro_wrap_maybe_start();
			}
			echo '<label><input type="radio"
				 id="' . esc_attr( $name . '__' . $key ) . '"
				 name="' . esc_attr( $name ) . '"
				 value="' . esc_attr( $key ) . '"';
			checked( $value, $key );
			disabled( $disabled || $item_disabled );
			echo ' />' . wp_kses( $label, self::get_allowed_html_for_wp_kses_from_content( $label ) ) . '</label>' . wp_kses( $postfix, self::get_allowed_html_for_wp_kses_from_content( $postfix ) ) . "\n";
			if ( $pro_feature ) {
				self::pro_wrap_description(
					$label_or_array['pro_excerpt'],
					$label_or_array['pro_description'],
					$name . '__' . $key
				);

				self::pro_wrap_maybe_end( $name . '__' . $key );
			}
		}
	}

	/**
	 * Echos an input text element
	 *
	 * @param string $id
	 * @param string $name
	 * @param string $value
	 * @param bool   $disabled
	 */
	public static function textarea( $id, $name, $value, $disabled = false ) {
		?>
		<textarea class="enabled" id="<?php echo esc_attr( $id ); ?>"
			name="<?php echo esc_attr( $name ); ?>" rows="5" cols=25 style="width: 100%"
			<?php disabled( $disabled ); ?>><?php echo esc_textarea( $value ); ?></textarea>
		<?php
	}

	/**
	 * Echos an input checkbox element
	 *
	 * @param string $id
	 * @param string $name
	 * @param bool   $state    whether checked or not.
	 * @param bool   $disabled
	 */
	public static function checkbox( $id, $name, $state, $disabled = false, $label = null ) {
		if ( ! is_null( $label ) ) {
			echo '<label>';
		}

		echo '<input type="hidden" name="' . esc_attr( $name ) . '"
			 value="' . esc_attr( ( ! $disabled ? '0' : ( $state ? '1' : '0' ) ) ) . '">' . "\n";
		echo '<input class="enabled" type="checkbox" id="' . esc_attr( $id ) . '"
			 name="' . esc_attr( $name ) . '" value="1" ';
		checked( $state );
		disabled( $disabled );
		echo ' /> ';

		if ( ! is_null( $label ) ) {
			echo wp_kses( $label, self::get_allowed_html_for_wp_kses_from_content( $label ) ) . '</label>';
		}
	}

	/**
	 * Echos an element
	 *
	 * @param string $type
	 * @param string $id
	 * @param string $name
	 * @param mixed  $value
	 * @param bool   $disabled
	 */
	public static function element( $type, $id, $name, $value, $disabled = false ) {
		switch ( $type ) {
			case 'textbox':
				self::textbox( $id, $name, $value, $disabled );
				break;
			case 'password':
				self::passwordbox( $id, $name, $value, $disabled );
				break;
			case 'textarea':
				self::textarea( $id, $name, $value, $disabled );
				break;
			case 'checkbox':
			default:
				self::checkbox( $id, $name, $value, $disabled );
				break;
		}
	}

	public static function checkbox2( $e ) {
		self::checkbox(
			$e['name'],
			$e['name'],
			$e['value'],
			( isset( $e['disabled'] ) ? $e['disabled'] : false ),
			( isset( $e['label'] ) ? $e['label'] : null )
		);
	}

	public static function radiogroup2( $e ) {
		self::radiogroup(
			$e['name'],
			$e['value'],
			$e['values'],
			$e['disabled'],
			$e['separator']
		);
	}

	public static function selectbox2( $e ) {
		self::selectbox(
			$e['name'],
			$e['name'],
			$e['value'],
			$e['values'],
			( isset( $e['disabled'] ) ? $e['disabled'] : false ),
			( isset( $e['optgroups'] ) ? $e['optgroups'] : null )
		);
	}

	public static function textbox2( $e ) {
		self::textbox(
			$e['name'],
			$e['name'],
			$e['value'],
			( isset( $e['disabled'] ) ? $e['disabled'] : false ),
			( ! empty( $e['size'] ) ? $e['size'] : 20 ),
			( ! empty( $e['type'] ) ? $e['type'] : 'text' ),
			( ! empty( $e['placeholder'] ) ? $e['placeholder'] : '' )
		);
	}

	public static function textarea2( $e ) {
		self::textarea(
			$e['name'],
			$e['name'],
			$e['value'],
			( isset( $e['disabled'] ) ? $e['disabled'] : false )
		);
	}

	public static function control2( $a ) {
		if ( 'checkbox' === $a['control'] ) {
			self::checkbox2(
				array(
					'name'     => $a['control_name'],
					'value'    => $a['value'],
					'disabled' => $a['disabled'],
					'label'    => $a['checkbox_label'],
				)
			);
		} elseif ( 'radiogroup' === $a['control'] ) {
			self::radiogroup2(
				array(
					'name'      => $a['control_name'],
					'value'     => $a['value'],
					'disabled'  => $a['disabled'],
					'values'    => $a['radiogroup_values'],
					'separator' => isset( $a['radiogroup_separator'] ) ? $a['radiogroup_separator'] : '',
				)
			);
		} elseif ( 'selectbox' === $a['control'] ) {
			self::selectbox2(
				array(
					'name'      => $a['control_name'],
					'value'     => $a['value'],
					'disabled'  => $a['disabled'],
					'values'    => $a['selectbox_values'],
					'optgroups' => isset( $a['selectbox_optgroups'] ) ? $a['selectbox_optgroups'] : null,
				)
			);
		} elseif ( 'textbox' === $a['control'] ) {
			self::textbox2(
				array(
					'name'        => $a['control_name'],
					'value'       => $a['value'],
					'disabled'    => $a['disabled'],
					'type'        => isset( $a['textbox_type'] ) ? $a['textbox_type'] : null,
					'size'        => isset( $a['textbox_size'] ) ? $a['textbox_size'] : null,
					'placeholder' => isset( $a['textbox_placeholder'] ) ? $a['textbox_placeholder'] : null,
				)
			);
		} elseif ( 'textarea' === $a['control'] ) {
			self::textarea2(
				array(
					'name'     => $a['control_name'],
					'value'    => $a['value'],
					'disabled' => $a['disabled'],
				)
			);
		} elseif ( 'none' === $a['control'] ) {
			echo wp_kses( $a['none_label'], self::get_allowed_html_for_wp_kses_from_content( $a['none_label'] ) );
		} elseif ( 'button' === $a['control'] ) {
			echo '<button type="button" class="button">' . wp_kses( $a['none_label'], self::get_allowed_html_for_wp_kses_from_content( $a['none_label'] ) ) . '</button>';
		}
	}

	/**
	 * Get table classes for tables including pro features.
	 *
	 * When on the free version, tables with pro features have additional classes added to help highlight
	 * the premium feature. If the user is on pro, this class is omitted.
	 *
	 * @since 0.14.3
	 *
	 * @return string
	 */
	public static function table_class() {
		$table_class[] = 'form-table';

		if ( ! Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			$table_class[] = 'w3tc-pro-feature';
		}

		return implode( ' ', $table_class );
	}

	/**
	 * Renders <tr> element with controls
	 * id =>
	 * label =>
	 * label_class =>
	 * <control> => details
	 * style - default is label,controls view,
	 *         alternative is one-column view
	 */
	public static function table_tr( $a ) {
		$id = isset( $a['id'] ) ? $a['id'] : '';
		$a  = apply_filters( 'w3tc_ui_settings_item', $a );

		echo '<tr><th';

		if ( isset( $a['label_class'] ) ) {
			echo ' class="' . esc_attr( $a['label_class'] ) . '"';
		}
		echo '>';
		if ( isset( $a['label'] ) ) {
			self::label( $id, $a['label'] );
		}

		echo "</th>\n<td>\n";

		foreach ( $a as $key => $e ) {
			if ( 'checkbox' === $key ) {
				self::checkbox(
					$id,
					isset( $e['name'] ) ? $e['name'] : null,
					$e['value'],
					( isset( $e['disabled'] ) ? $e['disabled'] : false ),
					( isset( $e['label'] ) ? $e['label'] : null )
				);
			} elseif ( 'description' === $key ) {
				echo '<p class="description">' . wp_kses( $e, self::get_allowed_html_for_wp_kses_from_content( $e ) ) . '</p>';
			} elseif ( 'hidden' === $key ) {
				self::hidden( '', $e['name'], $e['value'] );
			} elseif ( 'html' === $key ) {
				echo wp_kses( $e, self::get_allowed_html_for_wp_kses_from_content( $e ) );
			} elseif ( 'radiogroup' === $key ) {
				self::radiogroup(
					$e['name'],
					$e['value'],
					$e['values'],
					$e['disabled'],
					$e['separator']
				);
			} elseif ( 'selectbox' === $key ) {
				self::selectbox(
					$id,
					$e['name'],
					$e['value'],
					$e['values'],
					( isset( $e['disabled'] ) ? $e['disabled'] : false ),
					( isset( $e['optgroups'] ) ? $e['optgroups'] : null )
				);
			} elseif ( 'textbox' === $key ) {
				self::textbox(
					$id,
					$e['name'],
					$e['value'],
					( isset( $e['disabled'] ) ? $e['disabled'] : false ),
					( ! empty( $e['size'] ) ? $e['size'] : 20 ),
					( ! empty( $e['type'] ) ? $e['type'] : 'text' ),
					( ! empty( $e['placeholder'] ) ? $e['placeholder'] : '' )
				);
			} elseif ( 'textarea' === $key ) {
				self::textarea(
					$id,
					$e['name'],
					$e['value'],
					( isset( $e['disabled'] ) ? $e['disabled'] : false )
				);
			}
		}

		echo "</td></tr>\n";
	}

	/**
	 * Prints configuration item UI based on description
	 *   key => configuration key
	 *   label => configuration key's as its introduced to the user
	 *   value => it's value
	 *   disabled => if disabled
	 *
	 *   control => checkbox | radiogroup | selectbox | textbox
	 *   checkbox_label => text shown after the textbox
	 *   radiogroup_values => array of possible values for radiogroup
	 *   selectbox_values => array of possible values for dropdown
	 *   selectbox_optgroups =>
	 *   textbox_size =>
	 *
	 *   control_after => something after control to add
	 *   description => description shown to the user below
	 */
	public static function config_item( $a ) {
		/*
		 * Some items we do not want shown in the free edition.
		 *
		 * By default, they will show in free, unless 'show_in_free' is specifically passed in as false.
		 */
		$is_w3tc_free = ! Util_Environment::is_w3tc_pro( Dispatcher::config() );
		$show_in_free = ! isset( $a['show_in_free'] ) || (bool) $a['show_in_free'];
		if ( ! $show_in_free && $is_w3tc_free ) {
			return;
		}

		$a = self::config_item_preprocess( $a );

		if ( 'w3tc_single_column' === $a['label_class'] ) {
			echo '<tr><th colspan="2">';
		} else {
			echo '<tr><th class="' . esc_attr( $a['label_class'] ) . '">';

			if ( ! empty( $a['label'] ) ) {
				self::label( $a['control_name'], $a['label'] );
			}

			echo "</th>\n<td>\n";
		}

		self::control2( $a );

		if ( isset( $a['control_after'] ) ) {
			echo wp_kses(
				$a['control_after'],
				self::get_allowed_html_for_wp_kses_from_content( $a['control_after'] )
			);
		}
		if ( isset( $a['description'] ) ) {
			echo wp_kses(
				sprintf(
					'%1$s%2$s%3$s',
					'<p class="description">',
					$a['description'],
					'</p>'
				),
				array(
					'p'       => array(
						'class' => array(),
					),
					'acronym' => array(
						'title' => array(),
					),
				)
			);
		}

		echo ( isset( $a['style'] ) ? '</th>' : '</td>' );
		echo "</tr>\n";
	}

	public static function config_item_extension_enabled( $a ) {
		echo "<tr><th class=''></th>\n<td>\n";

		$c = Dispatcher::config();
		self::checkbox2(
			array(
				'name'  => 'extension__' . self::config_key_to_http_name( $a['extension_id'] ),
				'value' => $c->is_extension_active_frontend( $a['extension_id'] ),
				'label' => $a['checkbox_label'],
			)
		);

		if ( isset( $a['description'] ) ) {
			echo '<p class="description">' . wp_kses( $a['description'], self::get_allowed_html_for_wp_kses_from_content( $a['description'] ) ) . '</p>';
		}

		echo "</td></tr>\n";
	}

	public static function config_item_pro( $a ) {
		$a = self::config_item_preprocess( $a );

		if ( 'w3tc_no_trtd' !== $a['label_class'] ) {
			echo '<tr><th class="' . esc_attr( $a['label_class'] ) . '">';

			if ( ! empty( $a['label'] ) ) {
				self::label( $a['control_name'], $a['label'] );
			}

			echo "</th>\n<td>\n";
		}

		self::pro_wrap_maybe_start();

		self::control2( $a );

		if ( isset( $a['control_after'] ) ) {
			echo wp_kses( $a['control_after'], self::get_allowed_html_for_wp_kses_from_content( $a['control_after'] ) );
		}

		if ( isset( $a['description'] ) ) {
			self::pro_wrap_description( $a['excerpt'], $a['description'], $a['control_name'] );
		}

		self::pro_wrap_maybe_end( $a['control_name'] );

		if ( 'w3tc_no_trtd' !== $a['label_class'] ) {
			echo "</th></tr>\n";
		}
	}

	public static function config_item_preprocess( $a ) {
		$c = Dispatcher::config();

		if ( ! isset( $a['value'] ) || is_null( $a['value'] ) ) {
			$a['value'] = $c->get( $a['key'] );
			if ( is_array( $a['value'] ) ) {
				$a['value'] = implode( "\n", $a['value'] );
			}
		}

		if ( ! isset( $a['disabled'] ) || is_null( $a['disabled'] ) ) {
			$a['disabled'] = $c->is_sealed( $a['key'] );
		}

		if ( empty( $a['label'] ) ) {
			$a['label'] = self::config_label( $a['key'] );
		}

		$a['control_name'] = self::config_key_to_http_name( $a['key'] );
		$a['label_class']  = empty( $a['label_class'] ) ? '' : $a['label_class'];
		if ( empty( $a['label_class'] ) && 'checkbox' === $a['control'] ) {
			$a['label_class'] = 'w3tc_config_checkbox';
		}

		$action_key = $a['key'];
		if ( is_array( $action_key ) ) {
			$action_key = 'extension.' . $action_key[0] . '.' . $action_key[1];
		}

		return apply_filters( 'w3tc_ui_config_item_' . $action_key, $a );
	}

	/**
	 * Displays config item - caching engine selectbox
	 */
	public static function config_item_engine( $a ) {
		if ( isset( $a['empty_value'] ) && $a['empty_value'] ) {
			$values[''] = array(
				'label' => 'Please select a method',
			);
		}

		$values['file']         = array(
			'label'    => __( 'Disk', 'w3-total-cache' ),
			'optgroup' => 0,
		);
		$values['apc']          = array(
			'disabled' => ! Util_Installed::apc(),
			'label'    => __( 'Opcode: Alternative PHP Cache (APC / APCu)', 'w3-total-cache' ),
			'optgroup' => 1,
		);
		$values['eaccelerator'] = array(
			'disabled' => ! Util_Installed::eaccelerator(),
			'label'    => __( 'Opcode: eAccelerator', 'w3-total-cache' ),
			'optgroup' => 1,
		);
		$values['xcache']       = array(
			'disabled' => ! Util_Installed::xcache(),
			'label'    => __( 'Opcode: XCache', 'w3-total-cache' ),
			'optgroup' => 1,
		);
		$values['wincache']     = array(
			'disabled' => ! Util_Installed::wincache(),
			'label'    => __( 'Opcode: WinCache', 'w3-total-cache' ),
			'optgroup' => 1,
		);
		$values['memcached']    = array(
			'disabled' => ! Util_Installed::memcached(),
			'label'    => __( 'Memcached', 'w3-total-cache' ),
			'optgroup' => 2,
		);
		$values['redis']        = array(
			'disabled' => ! Util_Installed::redis(),
			'label'    => __( 'Redis', 'w3-total-cache' ),
			'optgroup' => 2,
		);

		self::config_item(
			array(
				'key'                 => $a['key'],
				'label'               => ( isset( $a['label'] ) ? $a['label'] : null ),
				'disabled'            => ( isset( $a['disabled'] ) ? $a['disabled'] : null ),
				'control'             => 'selectbox',
				'selectbox_values'    => $values,
				'selectbox_optgroups' => array(
					__( 'Shared Server:', 'w3-total-cache' ),
					__( 'Dedicated / Virtual Server:', 'w3-total-cache' ),
					__( 'Multiple Servers:', 'w3-total-cache' ),
				),
				'control_after'       => isset( $a['control_after'] ) ? $a['control_after'] : null,
			)
		);
	}

	public static function pro_wrap_maybe_start() {
		if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			return;
		}

		?>
		<div class="w3tc-gopro">
			<div>
		<?php
	}

	public static function pro_wrap_description( $excerpt_clean, $description, $data_href ) {
		echo '<p class="description w3tc-gopro-excerpt">' . wp_kses( $excerpt_clean, self::get_allowed_html_for_wp_kses_from_content( $excerpt_clean ) ) . '</p>';

		if ( ! empty( $description ) ) {
			$d = array_map(
				function( $e ) {
					return '<p class="description">' . wp_kses( $e, self::get_allowed_html_for_wp_kses_from_content( $e ) ) . '</p>';
				},
				$description
			);

			$descriptions = implode( "\n", $d );

			echo '<div class="w3tc-gopro-description">' . wp_kses( $descriptions, self::get_allowed_html_for_wp_kses_from_content( $descriptions ) ) . '</div>';
			echo '<a href="#" class="w3tc-gopro-more" data-href="w3tc-gopro-more-' . esc_url( $data_href ) . '">' . esc_html( __( 'Show More', 'w3-total-cache' ) ) . '<span class="dashicons dashicons-arrow-down-alt2"></span></a>';
		}
	}

	public static function pro_wrap_maybe_end( $button_data_src ) {
		if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			return;
		}

		?>
			</div>
			<div class="w3tc-gopro-action">
				<button class="button w3tc-gopro-button button-buy-plugin" data-src="<?php echo esc_attr( $button_data_src ); ?>">
					Learn more about Pro
				</button>
			</div>
		</div>
		<?php
	}

	public static function pro_wrap_maybe_start2() {
		if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			return;
		}

		?>
		<div class="updated w3tc_note" id="licensing_terms" style="display: flex; align-items: center">
			<p style="flex-grow: 1">
		<?php
	}

	public static function pro_wrap_maybe_end2( $button_data_src ) {
		if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
			return;
		}

		?>
			</p>
			<div style="text-align: right">
				<button class="button w3tc-gopro-button button-buy-plugin" data-src="<?php echo esc_attr( $button_data_src ); ?>">
					Unlock Feature
				</button>
			</div>
		</div>
		<?php
	}



	/**
	 * On subblogs - shows button to enable/disable custom configuration
	 *   $a['key'] - config key *_overloaded which are managed
	 */
	public static function config_overloading_button( $a ) {
		$c = Dispatcher::config();
		if ( $c->is_master() ) {
			return;
		}

		if ( $c->get_boolean( $a['key'] ) ) {
			$name  = 'w3tc_config_overloaded_disable~' . self::config_key_to_http_name( $a['key'] );
			$value = __( 'Use common settings', 'w3-total-cache' );
		} else {
			$name  = 'w3tc_config_overloaded_enable~' . self::config_key_to_http_name( $a['key'] );
			$value = __( 'Use specific settings', 'w3-total-cache' );
		}

		echo '<div style="float: right">';
		echo '<input type="submit" class="button"
			 name="' . esc_attr( $name ) . '"
			 value="' . esc_attr( $value ) . '" />';
		echo '</div>';
	}

	/**
	 * Get the admin URL based on the path and the interface (network or site).
	 *
	 * @param  string $path Admin path/URI.
	 * @return string
	 */
	public static function admin_url( $path ) {
		return is_network_admin() ? network_admin_url( $path ) : admin_url( $path );
	}

	/**
	 * Returns a preview link with current state
	 *
	 * @return string
	 */
	public static function preview_link() {
		return self::button_link(
			__( 'Preview', 'w3-total-cache' ),
			self::url( array( 'w3tc_default_previewing' => 'y' ) ),
			true
		);
	}

	/**
	 * Takes seconds and converts to array('Nh ','Nm ', 'Ns ', 'Nms ') or "Nh Nm Ns Nms"
	 *
	 * @param unknown $input
	 * @param bool    $string
	 * @return array|string
	 */
	public static function secs_to_time( $input, $string = true ) {
		$input   = (float) $input;
		$time    = array();
		$msecs   = floor( $input * 1000 % 1000 );
		$seconds = $input % 60;

		$minutes = floor( $input / 60 ) % 60;
		$hours   = floor( $input / 60 / 60 ) % 60;

		if ( $hours ) {
			$time[] = $hours;
		}
		if ( $minutes ) {
			$time[] = sprintf( '%dm', $minutes );
		}
		if ( $seconds ) {
			$time[] = sprintf( '%ds', $seconds );
		}
		if ( $msecs ) {
			$time[] = sprintf( '%dms', $msecs );
		}

		if ( empty( $time ) ) {
			$time[] = sprintf( '%dms', 0 );
		}
		if ( $string ) {
			return implode( ' ', $time );
		}
		return $time;
	}

	/**
	 * Returns option name accepted by W3TC as http paramter
	 * from it's id (full name from config file)
	 */
	public static function config_key_to_http_name( $id ) {
		if ( is_array( $id ) ) {
			$id = $id[0] . '___' . $id[1];
		}

		return str_replace( '.', '__', $id );
	}

	/*
	 * Converts configuration key returned in http _GET/_POST
	 * to configuration key
	 */
	public static function config_key_from_http_name( $http_key ) {
		$a = explode( '___', $http_key );
		if ( count( $a ) === 2 ) {
			$a[0] = self::config_key_from_http_name( $a[0] );
			$a[1] = self::config_key_from_http_name( $a[1] );
			return $a;
		}

		return str_replace( '__', '.', $http_key );
	}

	public static function get_allowed_html_for_wp_kses_from_content( $content ) {
		$allowed_html = array();

		if( empty( $content ) ) {
			return $allowed_html;
		}

		$dom = new DOMDocument();
		@$dom->loadHTML( $content );
		foreach ( $dom->getElementsByTagName( '*' ) as $tag ) {
			$tagname = $tag->tagName;
			foreach ( $tag->attributes as $attribute_name => $attribute_val ) {
				$allowed_html[ $tagname ][ $attribute_name ] = array();
			}
			$allowed_html[ $tagname ] = empty( $allowed_html[ $tagname ] ) ? array() : $allowed_html[ $tagname ];
		}
		return $allowed_html;
	}
}
