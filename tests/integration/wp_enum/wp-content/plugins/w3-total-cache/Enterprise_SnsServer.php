<?php
namespace W3TC;

/**
 * Purge using AmazonSNS object
 */
class Enterprise_SnsServer extends Enterprise_SnsBase {

	/**
	 * Processes message from SNS
	 *
	 * @throws Exception
	 */
	function process_message( $message ) {
		$this->_log( 'Received message' );

		try {
			$message = new \Aws\Sns\Message( $message );
			$validator = new \Aws\Sns\MessageValidator();
			$error = '';
			if ( $validator->isValid( $message ) ) {
				$topic_arn = $this->_config->get_string( 'cluster.messagebus.sns.topic_arn' );

				if ( empty( $topic_arn ) || $topic_arn != $message['TopicArn'] )
					throw new \Exception( 'Not my Topic. Request came from ' .
						$message['TopicArn'] );

				if ( $message['Type'] == 'SubscriptionConfirmation' )
					$this->_subscription_confirmation( $message );
				elseif ( $message['Type'] == 'Notification' )
					$this->_notification( $message['Message'] );
			} else {
				$this->_log( 'Error processing message it was not valid.' );
			}
		} catch ( \Exception $e ) {
			$this->_log( 'Error processing message: ' . $e->getMessage() );
		}
		$this->_log( 'Message processed' );
	}

	/**
	 * Confirms subscription
	 *
	 * @param Message $message
	 * @throws Exception
	 */
	private function _subscription_confirmation( $message ) {
		$this->_log( 'Issuing confirm_subscription' );
		$topic_arn = $this->_config->get_string( 'cluster.messagebus.sns.topic_arn' );

		$response = $this->_get_api()->confirmSubscription( array(
			'Token' => $message['Token'],
			'TopicArn' => $topic_arn
		) );
		$this->_log( 'Subscription confirmed: ' .
			( $response['@metadata']['statusCode'] == 200 ? 'OK' : 'Error' ) );
	}

	/**
	 * Processes notification
	 *
	 * @param array   $v
	 */
	private function _notification( $v ) {
		$m = json_decode( $v, true );
		if ( isset( $m['hostname'] ) )
			$this->_log( 'Message originated from hostname: ' . $m['hostname'] );

		define( 'DOING_SNS', true );
		$this->_log( 'Actions executing' );
		do_action( 'w3tc_messagebus_message_received' );

		if ( isset( $m['actions'] ) ) {
			$actions = $m['actions'];
			foreach ( $actions as $action )
				$this->_execute( $action );
		} else {
			$this->_execute( $m['action'] );
		}

		do_action( 'w3tc_messagebus_message_processed' );
		$this->_log( 'Actions executed' );
	}

	/**
	 * Execute action
	 *
	 * @param unknown $m
	 * @throws Exception
	 */
	private function _execute( $m ) {
		$action = $m['action'];
		$this->_log( 'Executing action ' . $action );
		//Needed for cache flushing
		$executor = new CacheFlush_Locally();
		//Needed for cache cleanup
		$pgcache_admin = Dispatcher::component( 'PgCache_Plugin_Admin' );

		//See which message we got
		if ( $action == 'dbcache_flush' )
			$executor->dbcache_flush();
		elseif ( $action == 'objectcache_flush' )
			$executor->objectcache_flush();
		elseif ( $action == 'fragmentcache_flush' )
			$executor->fragmentcache_flush();
		elseif ( $action == 'fragmentcache_flush_group' )
			$executor->fragmentcache_flush_group( $m['group'] );
		elseif ( $action == 'minifycache_flush' )
			$executor->minifycache_flush();
		elseif ( $action == 'browsercache_flush' )
			$executor->browsercache_flush();
		elseif ( $action == 'cdn_purge_all' )
			$executor->cdn_purge_all(
				isset( $m['extras'] ) ? $m['extras'] : null );
		elseif ( $action == 'cdn_purge_files' )
			$executor->cdn_purge_files( $m['purgefiles'] );
		elseif ( $action == 'pgcache_cleanup' )
			$pgcache_admin->cleanup_local();
		elseif ( $action == 'opcache_flush' )
			$executor->opcache_flush();
		elseif ( $action == 'flush_all' )
			$executor->flush_all(
				isset( $m['extras'] ) ? $m['extras'] : null );
		elseif ( $action == 'flush_group' )
			$executor->flush_group(
				isset( $m['group'] ) ? $m['group'] : null,
				isset( $m['extras'] ) ? $m['extras'] : null );
		elseif ( $action == 'flush_post' )
			$executor->flush_post( $m['post_id'] );
		elseif ( $action == 'flush_posts' )
			$executor->flush_posts();
		elseif ( $action == 'flush_url' )
			$executor->flush_url( $m['url'] );
		elseif ( $action == 'prime_post' )
			$executor->prime_post( $m['post_id'] );
		else
			throw new \Exception( 'Unknown action ' . $action );

		$executor->execute_delayed_operations();

		$this->_log( 'succeeded' );
	}
}
