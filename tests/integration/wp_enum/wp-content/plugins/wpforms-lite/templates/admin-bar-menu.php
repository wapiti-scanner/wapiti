<?php
/**
 * Forms selector for admin bar menu.
 *
 * @since 1.6.5
 *
 * @var array $forms_data Forms data.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$has_notifications = $forms_data['has_notifications'] ? ' wpforms-menu-form-notifications' : '';

end( $forms_data['forms'] );
$last_key = key( $forms_data['forms'] );
?>

<script type="text/html" id="tmpl-wpforms-admin-menubar-data">
<?php foreach ( $forms_data['forms'] as $key => $form ) : ?>
	<li id="wp-admin-bar-wpforms-form-id-<?php echo esc_attr( $form['form_id'] ); ?>" class="menupop wpforms-menu-form<?php echo $key === 0 ? esc_attr( $has_notifications ) : ''; ?><?php echo $key === $last_key ? ' wpforms-menu-form-last' : ''; ?>">
		<div class="ab-item ab-empty-item" aria-haspopup="true"><span class="wp-admin-bar-arrow" aria-hidden="true"></span><?php echo esc_html( $form['title'] ); ?></div>
		<div class="ab-sub-wrapper">
			<ul id="wp-admin-bar-wpforms-form-id-<?php echo esc_attr( $form['form_id'] ); ?>-default" class="ab-submenu">
			<?php if ( ! empty( $form['edit_url'] ) ) : ?>
				<li id="wp-admin-bar-wpforms-form-id-<?php echo esc_attr( $form['form_id'] ); ?>-edit">
					<a class="ab-item" href="<?php echo esc_url( $form['edit_url'] ); ?>"><?php echo esc_html( $forms_data['edit_text'] ); ?></a>
				</li>
			<?php endif; ?>
			<?php if ( ! empty( $form['entries_url'] ) ) : ?>
				<li id="wp-admin-bar-wpforms-form-id-<?php echo esc_attr( $form['form_id'] ); ?>-entries">
					<a class="ab-item" href="<?php echo esc_url( $form['entries_url'] ); ?>"><?php echo esc_html( $forms_data['entry_text'] ); ?></a>
				</li>
			<?php endif; ?>
			<?php if ( ! empty( $form['survey_url'] ) ) : ?>
				<li id="wp-admin-bar-wpforms-form-id-<?php echo esc_attr( $form['form_id'] ); ?>-survey">
					<a class="ab-item" href="<?php echo esc_url( $form['survey_url'] ); ?>"><?php echo esc_html( $forms_data['survey_text'] ); ?></a>
				</li>
			<?php endif; ?>
			</ul>
		</div>
	</li>
<?php endforeach; ?>
</script>
