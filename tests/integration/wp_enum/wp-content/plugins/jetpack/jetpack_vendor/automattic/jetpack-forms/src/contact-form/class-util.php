<?php
/**
 * Contact_Form_Util class.
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms\ContactForm;

/**
 * This class serves as a container for what previously were standalone grunion functions.
 * In the long term we should aim to move things to other classes and gradually get rid of this rather than adding more.
 */
class Util {

	/**
	 * Registers all relevant actions and filters for this class.
	 */
	public static function init() {
		if ( is_admin() ) {
			Admin::init();
		}

		add_filter( 'template_include', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_attribute' );

		add_action( 'render_block_core_template_part_post', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );
		add_action( 'render_block_core_template_part_file', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );
		add_action( 'render_block_core_template_part_none', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );
		add_action( 'gutenberg_render_block_core_template_part_post', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );
		add_action( 'gutenberg_render_block_core_template_part_file', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );
		add_action( 'gutenberg_render_block_core_template_part_none', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_set_block_template_part_id_global' );

		add_filter( 'render_block', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_unset_block_template_part_id_global', 10, 2 );
		add_filter( 'widget_block_content', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_contact_form_filter_widget_block_content', 1, 3 );

		add_action( 'init', '\Automattic\Jetpack\Forms\ContactForm\Contact_Form_Plugin::init', 9 );
		add_action( 'grunion_scheduled_delete', '\Automattic\Jetpack\Forms\ContactForm\Util::grunion_delete_old_spam' );
		add_action( 'grunion_pre_message_sent', '\Automattic\Jetpack\Forms\ContactForm\Util::jetpack_tracks_record_grunion_pre_message_sent', 12 );
	}

	/**
	 * Registers contact form block patterns.
	 */
	public static function register_pattern() {
		$category_slug = 'forms';
		register_block_pattern_category( $category_slug, array( 'label' => __( 'Forms', 'jetpack-forms' ) ) );

		$patterns = array(
			'contact-form'      => array(
				'title'      => 'Contact Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-textarea /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Contact Us","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
			'newsletter-form'   => array(
				'title'      => 'Newsletter Subscription Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-consent /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Subscribe","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
			'rsvp-form'         => array(
				'title'      => 'RSVP Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new RSVP from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-radio {"label":"Attending?","required":true,"options":["Yes","No"]} /-->
                        <!-- wp:jetpack/field-textarea {"label":"Other Details"} /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Send RSVP","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
			'registration-form' => array(
				'title'      => 'Registration Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new registration from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-telephone {"label":"Phone Number"} /-->
                        <!-- wp:jetpack/field-select {"label":"How did you hear about us?","options":["Search Engine","Social Media","TV","Radio","Friend or Family"]} /-->
                        <!-- wp:jetpack/field-textarea {"label":"Other Details"} /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Send","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
			'appointment-form'  => array(
				'title'      => 'Appointment Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"subject":"A new appointment booked from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-telephone {"required":true} /-->
                        <!-- wp:jetpack/field-date {"label":"Date","required":true} /-->
                        <!-- wp:jetpack/field-radio {"label":"Time","required":true,"options":["Morning","Afternoon"]} /-->
                        <!-- wp:jetpack/field-textarea {"label":"Notes"} /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Book Appointment","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
			'feedback-form'     => array(
				'title'      => 'Feedback Form',
				'blockTypes' => array( 'jetpack/contact-form' ),
				'categories' => array( $category_slug ),
				'content'    => '<!-- wp:jetpack/contact-form {"subject":"New feedback received from your website","style":{"spacing":{"padding":{"top":"16px","right":"16px","bottom":"16px","left":"16px"}}}} -->
                    <div class="wp-block-jetpack-contact-form" style="padding-top:16px;padding-right:16px;padding-bottom:16px;padding-left:16px">
                        <!-- wp:jetpack/field-name {"required":true} /-->
                        <!-- wp:jetpack/field-email {"required":true} /-->
                        <!-- wp:jetpack/field-radio {"label":"Please rate our website","required":true,"options":["1 - Very Bad","2 - Poor","3 - Average","4 - Good","5 - Excellent"]} /-->
                        <!-- wp:jetpack/field-textarea {"label":"How could we improve?"} /-->
                        <!-- wp:jetpack/button {"element":"button","text":"Send Feedback","lock":{"remove":true}} /-->
                    </div>
                    <!-- /wp:jetpack/contact-form -->',
			),
		);

		foreach ( $patterns as $name => $pattern ) {
			register_block_pattern( $name, $pattern );
		}
	}

	/**
	 * Sets the 'block_template' attribute on all instances of wp:jetpack/contact-form in
	 * the $_wp_current_template_content global variable.
	 *
	 * The $_wp_current_template_content global variable is hydrated immediately prior to
	 * 'template_include' in wp-includes/template-loader.php.
	 *
	 * This fixes Contact Form Blocks added to FSE _templates_ (e.g. Single or 404).
	 *
	 * @param string $template Template to be loaded.
	 */
	public static function grunion_contact_form_set_block_template_attribute( $template ) {
		global $_wp_current_template_content;
		if ( 'template-canvas.php' === basename( $template ) ) {
			Contact_Form::style_on();
			$_wp_current_template_content = self::grunion_contact_form_apply_block_attribute(
				$_wp_current_template_content,
				array(
					'block_template' => 'canvas',
				)
			);
		}
		return $template;
	}

	/**
	 * Sets the $grunion_block_template_part_id global.
	 *
	 * This is part of the fix for Contact Form Blocks added to FSE _template parts_ (e.g footer).
	 * The global is processed in Grunion_Contact_Form::parse().
	 *
	 * @param string $template_part_id ID for the currently rendered template part.
	 */
	public static function grunion_contact_form_set_block_template_part_id_global( $template_part_id ) {
		$GLOBALS['grunion_block_template_part_id'] = $template_part_id;
	}

	/**
	 * Unsets the global when block is done rendering.
	 *
	 * @param string $content Rendered block content.
	 * @param array  $block   The full block, including name and attributes.
	 * @return string
	 */
	public static function grunion_contact_form_unset_block_template_part_id_global( $content, $block ) {
		if ( 'core/template-part' === $block['blockName']
			&& isset( $GLOBALS['grunion_block_template_part_id'] ) ) {
			unset( $GLOBALS['grunion_block_template_part_id'] );
		}
		return $content;
	}

	/**
	 * Sets the 'widget' attribute on all instances of the contact form in the widget block.
	 *
	 * @param string          $content  Existing widget block content.
	 * @param array           $instance Array of settings for the current widget.
	 * @param WP_Widget_Block $widget   Current Block widget instance.
	 * @return string
	 */
	public static function grunion_contact_form_filter_widget_block_content( $content, $instance, $widget ) {
		Contact_Form::style_on();
		// Inject 'block_template' => <widget-id> into all instances of the contact form block.
		return self::grunion_contact_form_apply_block_attribute(
			$content,
			array(
				'widget' => $widget->id,
			)
		);
	}

	/**
	 * Deletes old spam feedbacks to keep the posts table size under control.
	 */
	public static function grunion_delete_old_spam() {
		global $wpdb;

		$grunion_delete_limit = 100;

		$now_gmt  = current_time( 'mysql', 1 );
		$sql      = $wpdb->prepare(
			"
			SELECT `ID`
			FROM $wpdb->posts
			WHERE DATE_SUB( %s, INTERVAL 15 DAY ) > `post_date_gmt`
				AND `post_type` = 'feedback'
				AND `post_status` = 'spam'
			LIMIT %d
		",
			$now_gmt,
			$grunion_delete_limit
		);
		$post_ids = $wpdb->get_col( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

		foreach ( (array) $post_ids as $post_id ) {
			// force a full delete, skip the trash
			wp_delete_post( $post_id, true );
		}

		if (
			/**
			 * Filter if the module run OPTIMIZE TABLE on the core WP tables.
			 *
			 * @module contact-form
			 *
			 * @since 1.3.1
			 * @since 6.4.0 Set to false by default.
			 *
			 * @param bool $filter Should Jetpack optimize the table, defaults to false.
			 */
			apply_filters( 'grunion_optimize_table', false )
		) {
			$wpdb->query( "OPTIMIZE TABLE $wpdb->posts" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		}

		// if we hit the max then schedule another run
		if ( count( $post_ids ) >= $grunion_delete_limit ) {
			wp_schedule_single_event( time() + 700, 'grunion_scheduled_delete' );
		}
	}

	/**
	 * Send an event to Tracks on form submission.
	 *
	 * @param int $post_id - the post_id for the CPT that is created.
	 *
	 * @return null|void
	 */
	public static function jetpack_tracks_record_grunion_pre_message_sent( $post_id ) {
		$post = get_post( $post_id );
		if ( $post ) {
			$extra = gmdate( 'Y-W', strtotime( $post->post_date_gmt ) );
		} else {
			$extra = 'no-post';
		}

		/** This action is documented in jetpack/modules/widgets/social-media-icons.php */
		do_action( 'jetpack_bump_stats_extras', 'jetpack_forms_message_sent', $extra );
	}

	/**
	 * Adds a given attribute to all instances of the Contact Form block.
	 *
	 * @param string $content  Existing content to process.
	 * @param array  $new_attr New attributes to add.
	 * @return string
	 */
	public static function grunion_contact_form_apply_block_attribute( $content, $new_attr ) {
		if ( false === stripos( $content, 'wp:jetpack/contact-form' ) ) {
			return $content;
		}
		return preg_replace_callback(
			'/<!--\s+(?P<closer>\/)?wp:jetpack\/?contact-form\s+(?P<attrs>{(?:(?:[^}]+|}+(?=})|(?!}\s+\/?-->).)*+)?}\s+)?(?P<void>\/)?-->/s',
			function ( $match ) use ( $new_attr ) {
				// Ignore block closers.
				if ( ! empty( $match['closer'] ) ) {
					return $match[0];
				}
				// If block doesn't have attributes, add our own.
				if ( empty( $match['attrs'] ) ) {
					return str_replace(
						'wp:jetpack/contact-form ',
						'wp:jetpack/contact-form ' . wp_json_encode( $new_attr ) . ' ',
						$match[0]
					);
				}
				// $match['attrs'] includes trailing space: '{"customThankyou":"message"} '.
				$attrs = json_decode( rtrim( $match['attrs'], ' ' ), true );
				$attrs = array_merge( $attrs, $new_attr );
				return str_replace(
					$match['attrs'],
					wp_json_encode( $attrs ) . ' ',
					$match[0]
				);
			},
			$content
		);
	}
}
