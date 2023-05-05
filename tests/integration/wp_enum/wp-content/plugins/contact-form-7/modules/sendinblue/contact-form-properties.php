<?php

add_filter(
	'wpcf7_pre_construct_contact_form_properties',
	'wpcf7_sendinblue_register_property',
	10, 2
);

/**
 * Registers the sendinblue contact form property.
 */
function wpcf7_sendinblue_register_property( $properties, $contact_form ) {
	$service = WPCF7_Sendinblue::get_instance();

	if ( $service->is_active() ) {
		$properties += array(
			'sendinblue' => array(),
		);
	}

	return $properties;
}


add_action(
	'wpcf7_save_contact_form',
	'wpcf7_sendinblue_save_contact_form',
	10, 3
);

/**
 * Saves the sendinblue property value.
 */
function wpcf7_sendinblue_save_contact_form( $contact_form, $args, $context ) {
	$service = WPCF7_Sendinblue::get_instance();

	if ( ! $service->is_active() ) {
		return;
	}

	$prop = isset( $_POST['wpcf7-sendinblue'] )
		? (array) $_POST['wpcf7-sendinblue']
		: array();

	$prop = wp_parse_args(
		$prop,
		array(
			'enable_contact_list' => false,
			'contact_lists' => array(),
			'enable_transactional_email' => false,
			'email_template' => 0,
		)
	);

	$prop['contact_lists'] = array_map( 'absint', $prop['contact_lists'] );

	$prop['email_template'] = absint( $prop['email_template'] );

	$contact_form->set_properties( array(
		'sendinblue' => $prop,
	) );
}


add_filter(
	'wpcf7_editor_panels',
	'wpcf7_sendinblue_editor_panels',
	10, 1
);

/**
 * Builds the editor panel for the sendinblue property.
 */
function wpcf7_sendinblue_editor_panels( $panels ) {
	$service = WPCF7_Sendinblue::get_instance();

	if ( ! $service->is_active() ) {
		return $panels;
	}

	$contact_form = WPCF7_ContactForm::get_current();

	$prop = wp_parse_args(
		$contact_form->prop( 'sendinblue' ),
		array(
			'enable_contact_list' => false,
			'contact_lists' => array(),
			'enable_transactional_email' => false,
			'email_template' => 0,
		)
	);

	$editor_panel = function () use ( $prop, $service ) {

		$description = sprintf(
			esc_html(
				__( "You can set up the Sendinblue integration here. For details, see %s.", 'contact-form-7' )
			),
			wpcf7_link(
				__( 'https://contactform7.com/sendinblue-integration/', 'contact-form-7' ),
				__( 'Sendinblue integration', 'contact-form-7' )
			)
		);

		$lists = $service->get_lists();
		$templates = $service->get_templates();

?>
<h2><?php echo esc_html( __( 'Sendinblue', 'contact-form-7' ) ); ?></h2>

<fieldset>
	<legend><?php echo $description; ?></legend>

	<table class="form-table" role="presentation">
		<tbody>
			<tr class="<?php echo $prop['enable_contact_list'] ? '' : 'inactive'; ?>">
				<th scope="row">
		<?php

		echo esc_html( __( 'Contact lists', 'contact-form-7' ) );

		?>
				</th>
				<td>
					<fieldset>
						<legend class="screen-reader-text">
		<?php

		echo esc_html( __( 'Contact lists', 'contact-form-7' ) );

		?>
						</legend>
						<label for="wpcf7-sendinblue-enable-contact-list">
							<input type="checkbox" name="wpcf7-sendinblue[enable_contact_list]" id="wpcf7-sendinblue-enable-contact-list" value="1" <?php checked( $prop['enable_contact_list'] ); ?> />
		<?php

		echo esc_html(
			__( "Add form submitters to your contact lists", 'contact-form-7' )
		);

		?>
						</label>
					</fieldset>
				</td>
			</tr>
			<tr>
				<th scope="row"></th>
				<td>
					<fieldset>
		<?php

		if ( $lists ) {
			echo sprintf(
				'<legend>%1$s</legend>',
				esc_html( __( 'Select lists to which contacts are added:', 'contact-form-7' ) )
			);

			echo '<ul>';

			foreach ( $lists as $list ) {
				echo sprintf(
					'<li><label><input %1$s /> %2$s</label></li>',
					wpcf7_format_atts( array(
						'type' => 'checkbox',
						'name' => 'wpcf7-sendinblue[contact_lists][]',
						'value' => $list['id'],
						'checked' => in_array( $list['id'], $prop['contact_lists'] ),
					) ),
					esc_html( $list['name'] )
				);
			}

			echo '</ul>';
		} else {
			echo sprintf(
				'<legend>%1$s</legend>',
				esc_html( __( 'You have no contact list yet.', 'contact-form-7' ) )
			);
		}

		?>
					</fieldset>
		<?php

		echo sprintf(
			'<p><a %1$s>%2$s <span class="screen-reader-text">%3$s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
			wpcf7_format_atts( array(
				'href' => 'https://my.sendinblue.com/lists',
				'target' => '_blank',
				'rel' => 'external noreferrer noopener',
			) ),
			esc_html( __( 'Manage your contact lists', 'contact-form-7' ) ),
			esc_html( __( '(opens in a new tab)', 'contact-form-7' ) )
		);

		?>
				</td>
			</tr>
			<tr class="<?php echo $prop['enable_transactional_email'] ? '' : 'inactive'; ?>">
				<th scope="row">
		<?php

		echo esc_html( __( 'Welcome email', 'contact-form-7' ) );

		?>
				</th>
				<td>
					<fieldset>
						<legend class="screen-reader-text">
		<?php

		echo esc_html( __( 'Welcome email', 'contact-form-7' ) );

		?>
						</legend>
						<label for="wpcf7-sendinblue-enable-transactional-email">
							<input type="checkbox" name="wpcf7-sendinblue[enable_transactional_email]" id="wpcf7-sendinblue-enable-transactional-email" value="1" <?php checked( $prop['enable_transactional_email'] ); ?> />
		<?php

		echo esc_html(
			__( "Send a welcome email to new contacts", 'contact-form-7' )
		);

		?>
						</label>
					</fieldset>
				</td>
			</tr>
			<tr>
				<th scope="row"></th>
				<td>
					<fieldset>
		<?php

		if ( $templates ) {
			echo sprintf(
				'<legend>%1$s</legend>',
				esc_html( __( 'Select an email template:', 'contact-form-7' ) )
			);

			echo '<select name="wpcf7-sendinblue[email_template]">';

			echo sprintf(
				'<option %1$s>%2$s</option>',
				wpcf7_format_atts( array(
					'value' => 0,
					'selected' => 0 === $prop['email_template'],
				) ),
				esc_html( __( '&mdash; Select &mdash;', 'contact-form-7' ) )
			);

			foreach ( $templates as $template ) {
				echo sprintf(
					'<option %1$s>%2$s</option>',
					wpcf7_format_atts( array(
						'value' => $template['id'],
						'selected' => $prop['email_template'] === $template['id'],
					) ),
					esc_html( $template['name'] )
				);
			}

			echo '</select>';
		} else {
			echo sprintf(
				'<legend>%1$s</legend>',
				esc_html( __( 'You have no active email template yet.', 'contact-form-7' ) )
			);
		}

		?>
					</fieldset>
		<?php

		echo sprintf(
			'<p><a %1$s>%2$s <span class="screen-reader-text">%3$s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
			wpcf7_format_atts( array(
				'href' => 'https://my.sendinblue.com/camp/lists/template',
				'target' => '_blank',
				'rel' => 'external noreferrer noopener',
			) ),
			esc_html( __( 'Manage your email templates', 'contact-form-7' ) ),
			esc_html( __( '(opens in a new tab)', 'contact-form-7' ) )
		);

		?>
				</td>
			</tr>
		</tbody>
	</table>
</fieldset>
<?php
	};

	$panels += array(
		'sendinblue-panel' => array(
			'title' => __( 'Sendinblue', 'contact-form-7' ),
			'callback' => $editor_panel,
		),
	);

	return $panels;
}
