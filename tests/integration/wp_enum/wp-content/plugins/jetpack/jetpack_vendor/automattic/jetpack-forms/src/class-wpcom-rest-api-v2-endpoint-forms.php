<?php
/**
 * The Forms Rest Controller class.
 * Registers the REST routes for Jetpack Forms (taken from stats-admin).
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms;

use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Forms\ContactForm\Contact_Form;
use Automattic\Jetpack\Forms\ContactForm\Contact_Form_Plugin;
use WP_Error;
use WP_REST_Controller;
use WP_REST_Server;
/**
 * Handles the REST routes for Form Responses, aka Feedback.
 */
class WPCOM_REST_API_V2_Endpoint_Forms extends WP_REST_Controller {
	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->namespace = 'wpcom/v2';
		$this->rest_base = 'forms';

		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
	}

	/**
	 * Registers the REST routes.
	 *
	 * @access public
	 */
	public function register_rest_routes() {
		// Stats for single resource type.

		register_rest_route(
			$this->namespace,
			$this->rest_base . '/responses',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_responses' ),
				'permission_callback' => array( $this, 'get_responses_permission_check' ),
				'args'                => array(
					'limit'   => array(
						'default'  => 20,
						'type'     => 'integer',
						'required' => false,
						'minimum'  => 1,
					),
					'offset'  => array(
						'default'  => 0,
						'type'     => 'integer',
						'required' => false,
						'minimum'  => 0,
					),
					'form_id' => array(
						'type'     => 'integer',
						'required' => false,
						'minimum'  => 1,
					),
					'search'  => array(
						'type'     => 'string',
						'required' => false,
					),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			$this->rest_base . '/responses/bulk_actions',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'bulk_actions' ),
				'permission_callback' => array( $this, 'get_responses_permission_check' ),
			)
		);
	}

	/**
	 * Returns Jetpack Forms responses.
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return WP_REST_Response A response object containing Jetpack Forms responses.
	 */
	public function get_responses( $request ) {
		$args = array(
			'post_type'   => 'feedback',
			'post_status' => array( 'publish', 'draft' ),
		);

		if ( isset( $request['parent_id'] ) ) {
			$args['post_parent'] = $request['parent_id'];
		}

		if ( isset( $request['month'] ) ) {
			$args['m'] = $request['month'];
		}

		if ( isset( $request['limit'] ) ) {
			$args['posts_per_page'] = $request['limit'];
		}

		if ( isset( $request['offset'] ) ) {
			$args['offset'] = $request['offset'];
		}

		if ( isset( $request['search'] ) ) {
			$args['s'] = $request['search'];
		}

		$filter_args = array_merge(
			$args,
			array( 'post_status' => array( 'draft', 'publish', 'spam', 'trash' ) )
		);

		$query = array(
			'inbox' => new \WP_Query(
				array_merge(
					$args,
					array( 'post_status' => array( 'draft', 'publish' ) )
				)
			),
			'spam'  => new \WP_Query(
				array_merge(
					$args,
					array( 'post_status' => array( 'spam' ) )
				)
			),
			'trash' => new \WP_Query(
				array_merge(
					$args,
					array( 'post_status' => array( 'trash' ) )
				)
			),
		);

		$current_query = 'inbox';
		if ( isset( $request['status'] ) && in_array( $request['status'], array( 'spam', 'trash' ), true ) ) {
			$current_query = $request['status'];
		}

		$source_ids = Contact_Form_Plugin::get_all_parent_post_ids(
			array_diff_key( $filter_args, array( 'post_parent' => '' ) )
		);

		$responses = array_map(
			function ( $response ) {
				$data = \Automattic\Jetpack\Forms\ContactForm\Contact_Form_Plugin::parse_fields_from_content( $response->ID );

				return array(
					'id'                      => $response->ID,
					'uid'                     => $data['all_fields']['feedback_id'],
					'date'                    => get_the_date( 'c', $response ),
					'author_name'             => $data['_feedback_author'],
					'author_email'            => $data['_feedback_author_email'],
					'author_url'              => $data['_feedback_author_url'],
					'author_avatar'           => empty( $data['_feedback_author_email'] ) ? '' : get_avatar_url( $data['_feedback_author_email'] ),
					'email_marketing_consent' => $data['all_fields']['email_marketing_consent'],
					'ip'                      => $data['_feedback_ip'],
					'entry_title'             => $data['all_fields']['entry_title'],
					'entry_permalink'         => $data['all_fields']['entry_permalink'],
					'subject'                 => $data['_feedback_subject'],
					'fields'                  => array_diff_key(
						$data['all_fields'],
						array(
							'email_marketing_consent' => '',
							'entry_title'             => '',
							'entry_permalink'         => '',
							'feedback_id'             => '',
						)
					),
				);
			},
			$query[ $current_query ]->posts
		);

		return rest_ensure_response(
			array(
				'responses'         => $responses,
				'totals'            => array_map(
					function ( $subquery ) {
						return $subquery->found_posts;
					},
					$query
				),
				'filters_available' => array(
					'month'  => $this->get_months_filter_for_query( $filter_args ),
					'source' => array_map(
						function ( $post_id ) {
							return array(
								'id'    => $post_id,
								'title' => get_the_title( $post_id ),
								'url'   => get_permalink( $post_id ),
							);
						},
						$source_ids
					),
				),
			)
		);
	}

	/**
	 * Returns a list of months which can be used to filter the given query.
	 *
	 * @param array $query Query.
	 *
	 * @return array List of months.
	 */
	private function get_months_filter_for_query( $query ) {
		global $wpdb;

		$filters = '';

		if ( isset( $query['post_parent'] ) ) {
			$filters = $wpdb->prepare( 'AND post_parent = %d ', $query['post_parent'] );
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$months = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DISTINCT YEAR( post_date ) AS year, MONTH( post_date ) AS month
				FROM $wpdb->posts
				WHERE post_type = 'feedback'
				$filters
				ORDER BY post_date DESC"
			)
		);
		// phpcs:enable

		return array_map(
			function ( $row ) {
				return array(
					'month' => intval( $row->month ),
					'year'  => intval( $row->year ),
				);
			},
			$months
		);
	}

	/**
	 * Handles bulk actions for Jetpack Forms responses.
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 *
	 * @return WP_REST_Response A response object..
	 */
	public function bulk_actions( $request ) {
		$action   = $request->get_param( 'action' );
		$post_ids = $request->get_param( 'post_ids' );

		if ( $action && ! is_array( $post_ids ) ) {
			return new $this->error_response( __( 'Bad request', 'jetpack-forms' ), 400 );
		}

		switch ( $action ) {
			case 'mark_as_spam':
				return $this->bulk_action_mark_as_spam( $post_ids );

			case 'mark_as_not_spam':
				return $this->bulk_action_mark_as_not_spam( $post_ids );

			case 'trash':
				return $this->bulk_action_trash( $post_ids );

			case 'untrash':
				return $this->bulk_action_untrash( $post_ids );

			case 'delete':
				return $this->bulk_action_delete_forever( $post_ids );

			default:
				return $this->error_response( __( 'Bad request', 'jetpack-forms' ), 400 );
		}
	}

	/**
	 * Verifies that the current user has the requird capability for viewing form responses.
	 *
	 * @return true|WP_Error Returns true if the user has the required capability, else a WP_Error object.
	 */
	public function get_responses_permission_check() {
		$site_id = Manager::get_site_id();
		if ( is_wp_error( $site_id ) ) {
			return $site_id;
		}

		if ( ! current_user_can( 'manage_options' ) || ! is_user_member_of_blog( get_current_user_id(), $site_id ) ) {
			return new WP_Error(
				'invalid_user_permission_jetpack_form_responses',
				'unauthorized',
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return true;
	}

	/**
	 * Marks all feedback posts matchin the given IDs as spam.
	 *
	 * @param  array $post_ids Array of post IDs.
	 * @return WP_REST_Response
	 */
	private function bulk_action_mark_as_spam( $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			$post              = get_post( $post_id );
			$post->post_status = 'spam';
			$status            = wp_insert_post( $post );

			if ( ! $status || is_wp_error( $status ) ) {
				return $this->error_response(
					sprintf(
						/* translators: %s: Post ID */
						__( 'Failed to mark post as spam. Post ID: %d.', 'jetpack-forms' ),
						$post_id
					),
					500
				);
			}

			/** This action is documented in \Automattic\Jetpack\Forms\ContactForm\Admin */
			do_action(
				'contact_form_akismet',
				'spam',
				get_post_meta( $post_id, '_feedback_akismet_values', true )
			);
		}

		return new \WP_REST_Response( array(), 200 );
	}

	/**
	 * Marks all feedback posts matchin the given IDs as not spam.
	 *
	 * @param  array $post_ids Array of post IDs.
	 * @return WP_REST_Response
	 */
	private function bulk_action_mark_as_not_spam( $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			$post              = get_post( $post_id );
			$post->post_status = 'publish';
			$status            = wp_insert_post( $post );

			if ( ! $status || is_wp_error( $status ) ) {
				return $this->error_response(
					sprintf(
						/* translators: %s: Post ID */
						__( 'Failed to mark post as not-spam. Post ID: %d.', 'jetpack-forms' ),
						$post_id
					),
					500
				);
			}

			/** This action is documented in \Automattic\Jetpack\Forms\ContactForm\Admin */
			do_action(
				'contact_form_akismet',
				'ham',
				get_post_meta( $post_id, '_feedback_akismet_values', true )
			);

			// Maybe resend the original email
			$email          = get_post_meta( $post_id, '_feedback_email', true );
			$content_fields = Contact_Form_Plugin::parse_fields_from_content( $post_id );

			if ( empty( $email ) || empty( $content_fields ) ) {
				continue;
			}

			$blog_url             = wp_parse_url( site_url() );
			$headers              = isset( $email['headers'] ) ? $email['headers'] : false;
			$to                   = isset( $email['to'] ) ? $email['to'] : false;
			$comment_author_email = isset( $content_fields['_feedback_author_email'] ) ? $content_fields['_feedback_author_email'] : false;
			$message              = isset( $email['message'] ) ? $email['message'] : false;
			$reply_to_addr        = false;

			if ( ! $headers ) {
				$headers = 'From: "' . $content_fields['_feedback_author'] . '" <wordpress@' . $blog_url['host'] . ">\r\n";

				if ( ! empty( $comment_author_email ) ) {
					$reply_to_addr = $comment_author_email;
				} elseif ( is_array( $to ) ) {
					$reply_to_addr = $to[0];
				}

				if ( $reply_to_addr ) {
					$headers .= 'Reply-To: "' . $content_fields['_feedback_author'] . '" <' . $reply_to_addr . ">\r\n";
				}

				$headers .= 'Content-Type: text/plain; charset="' . get_option( 'blog_charset' ) . '"';
			}

			/**
			 * Filters the subject of the email sent after a contact form submission.
			 *
			 * @module contact-form
			 *
			 * @since 3.0.0
			 *
			 * @param string $content_fields['_feedback_subject'] Feedback's subject line.
			 * @param array $content_fields['_feedback_all_fields'] Feedback's data from old fields.
			 */
			$subject = apply_filters( 'contact_form_subject', $content_fields['_feedback_subject'], $content_fields['_feedback_all_fields'] );

			Contact_Form::wp_mail( $to, $subject, $message, $headers );
		}

		return new \WP_REST_Response( array(), 200 );
	}

	/**
	 * Moves all feedback posts matchin the given IDs to trash.
	 *
	 * @param  array $post_ids Array of post IDs.
	 * @return WP_REST_Response
	 */
	private function bulk_action_trash( $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			if ( ! wp_trash_post( $post_id ) ) {
				return $this->error_response(
					sprintf(
						/* translators: %s: Post ID */
						__( 'Failed to move post to trash. Post ID: %d.', 'jetpack-forms' ),
						$post_id
					),
					500
				);
			}
		}

		return new \WP_REST_Response( array(), 200 );
	}

	/**
	 * Removes all feedback posts matchin the given IDs from trash.
	 *
	 * @param  array $post_ids Array of post IDs.
	 * @return WP_REST_Response
	 */
	private function bulk_action_untrash( $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			if ( ! wp_untrash_post( $post_id ) ) {
				return $this->error_response(
					sprintf(
						/* translators: %s: Post ID */
						__( 'Failed to remove post from trash. Post ID: %d.', 'jetpack-forms' ),
						$post_id
					),
					500
				);
			}
		}

		return new \WP_REST_Response( array(), 200 );
	}

	/**
	 * Deletes all feedback posts matchin the given IDs.
	 *
	 * @param  array $post_ids Array of post IDs.
	 * @return WP_REST_Response
	 */
	private function bulk_action_delete_forever( $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			if ( ! wp_delete_post( $post_id ) ) {
				return $this->error_response(
					sprintf(
						/* translators: %s: Post ID */
						__( 'Failed to delete post. Post ID: %d.', 'jetpack-forms' ),
						$post_id
					),
					500
				);
			}
		}

		return new \WP_REST_Response( array(), 200 );
	}

	/**
	 * Returns a \WP_REST_Response containing the given error message and code.
	 *
	 * @param  string $message Error message.
	 * @param  int    $code    Error code.
	 * @return \WP_REST_Response
	 */
	private function error_response( $message, $code ) {
		return new \WP_REST_Response( array( 'error' => $message ), $code );
	}
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	wpcom_rest_api_v2_load_plugin( 'Automattic\Jetpack\Forms\WPCOM_REST_API_V2_Endpoint_Forms' );
}
