import { __ } from '@wordpress/i18n';
import React from 'react';

/**
 * BackupPromotion component definition.
 *
 * @returns {React.Component} BackupPromotion component.
 */
export default function BackupPromotion() {
	return (
		<div className="jp-backup-dashboard-promotion">
			<h3>
				{ __(
					'Save every change and get back online quickly with one‑click restores.',
					'jetpack-backup-pkg'
				) }
			</h3>
			<ul className="jp-product-promote">
				<li>{ __( 'Automated real-time backups', 'jetpack-backup-pkg' ) }</li>
				<li>{ __( 'Easy one-click restores', 'jetpack-backup-pkg' ) }</li>
				<li>{ __( 'Complete list of all site changes', 'jetpack-backup-pkg' ) }</li>
				<li>{ __( 'Global server infrastructure', 'jetpack-backup-pkg' ) }</li>
				<li>{ __( 'Best-in-class support', 'jetpack-backup-pkg' ) }</li>
			</ul>
		</div>
	);
}
