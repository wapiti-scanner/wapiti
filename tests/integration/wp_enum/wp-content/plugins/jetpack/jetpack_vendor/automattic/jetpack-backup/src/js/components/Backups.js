import { getProductCheckoutUrl, getRedirectUrl } from '@automattic/jetpack-components';
import { ExternalLink } from '@wordpress/components';
import { useSelect } from '@wordpress/data';
import { getDate, dateI18n } from '@wordpress/date';
import { createInterpolateElement, useCallback } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { BACKUP_STATE } from '../constants';
import useAnalytics from '../hooks/useAnalytics';
import useBackupsState from '../hooks/useBackupsState.js';
import { STORE_ID } from '../store';
import StatBlock from './StatBlock';
import './backups-style.scss';
import { StorageUsageLevels } from './backup-storage-space/storage-usage-levels';
import BackupAnim1 from './icons/backup-animation-1.svg';
import BackupAnim2 from './icons/backup-animation-2.svg';
import BackupAnim3 from './icons/backup-animation-3.svg';
import CloudAlertIcon from './icons/cloud-alert.svg';
import CloudIcon from './icons/cloud.svg';
import PluginsIcon from './icons/plugins.svg';
import PostsIcon from './icons/posts.svg';
import ThemesIcon from './icons/themes.svg';
import UploadsIcon from './icons/uploads.svg';
import WarningIcon from './icons/warning.svg';

/* eslint react/react-in-jsx-scope: 0 */
const Backups = () => {
	const { backupState, latestTime, progress, stats } = useBackupsState();

	return (
		<div className="jp-wrap jp-content backup-panel">
			{ BACKUP_STATE.LOADING === backupState && <Loading /> }
			{ BACKUP_STATE.NO_BACKUPS === backupState && <InProgressBackup progress={ progress } /> }
			{ BACKUP_STATE.NO_BACKUPS_RETRY === backupState && (
				<InProgressBackup progress={ progress } showProgressBar={ false } />
			) }
			{ BACKUP_STATE.IN_PROGRESS === backupState && <InProgressBackup progress={ progress } /> }
			{ BACKUP_STATE.COMPLETE === backupState && (
				<CompleteBackup latestTime={ latestTime } stats={ stats } />
			) }
			{ BACKUP_STATE.NO_GOOD_BACKUPS === backupState && <NoGoodBackups /> }
		</div>
	);
};

const NoGoodBackups = () => {
	const domain = useSelect( select => select( STORE_ID ).getCalypsoSlug(), [] );
	return (
		<div className="jp-row">
			<div className="lg-col-span-5 md-col-span-4 sm-col-span-4">
				<img src={ CloudAlertIcon } alt="" />
				<h1>{ __( "We're having trouble backing up your site", 'jetpack-backup-pkg' ) }</h1>
				<p>
					{ createInterpolateElement(
						__(
							' <a>Get in touch with us</a> to get your site backups going again.',
							'jetpack-backup-pkg'
						),
						{
							a: (
								<a
									//TODO: we may want to add a specific redirect for Backup plugin related issues
									href={ getRedirectUrl( 'jetpack-contact-support', { site: domain } ) }
									target="_blank"
									rel="noreferrer"
								/>
							),
						}
					) }
				</p>
			</div>
			<div className="lg-col-span-1 md-col-span-4 sm-col-span-0"></div>
			<div className="lg-col-span-6 md-col-span-2 sm-col-span-2"></div>
		</div>
	);
};

const Loading = () => {
	return <div className="jp-row"></div>;
};

const formatDateString = dateString => {
	const todayString = __( 'Today', 'jetpack-backup-pkg' );
	const todayDate = getDate();
	let backupDate = todayString;
	if ( dateI18n( 'zY', todayDate ) !== dateI18n( 'zY', dateString ) ) {
		backupDate = dateI18n( 'M j', dateString );
	}
	const backupTime = dateI18n( 'g:i A', dateString );

	return backupDate + ', ' + backupTime;
};

const CompleteBackup = ( { latestTime, stats } ) => {
	const domain = useSelect( select => select( STORE_ID ).getCalypsoSlug(), [] );
	const { tracks } = useAnalytics();
	const trackSeeBackupsCtaClick = useCallback( () => {
		tracks.recordEvent( 'jetpack_backup_see_backups_cta_click', { site: domain } );
	}, [ tracks, domain ] );

	const trackRecentRestorePointClick = useCallback( () => {
		tracks.recordEvent( 'jetpack_backup_view_recent_restore_points_click', { site: domain } );
	}, [ tracks, domain ] );

	const storageUsageLevel = useSelect( select => select( STORE_ID ).getStorageUsageLevel() );
	const storageLimit = useSelect( select => select( STORE_ID ).getBackupStorageLimit() ) ?? 0;
	const storageSize = useSelect( select => select( STORE_ID ).getBackupSize() ) ?? 0;
	const storageOverlimit = storageSize > storageLimit;
	const backupsStopped = storageUsageLevel === StorageUsageLevels.Full;

	const addonSlug = useSelect( select => select( STORE_ID ).getStorageAddonOfferSlug() );
	const siteSlug = useSelect( select => select( STORE_ID ).getCalypsoSlug() );
	const adminUrl = useSelect( select => select( STORE_ID ).getSiteData().adminUrl );

	const trackUpgradeStorageClick = useCallback( () => {
		tracks.recordEvent( 'jetpack_backup_upgrade_storage_header_cta', { site: domain } );
	}, [ tracks, domain ] );

	return (
		<div className="jp-row">
			<div className="lg-col-span-4 md-col-span-4 sm-col-span-4">
				{ ! backupsStopped && (
					<>
						<div className="backup__latest">
							<img
								src={ CloudIcon }
								alt=""
								className={ stats.warnings ? 'backup__warning-color' : '' }
							/>
							<h2>{ __( 'Latest Backup', 'jetpack-backup-pkg' ) }</h2>
						</div>
						<h1>{ formatDateString( latestTime ) }</h1>
					</>
				) }

				{ backupsStopped && (
					<>
						<div className="backup__latest">
							<img src={ WarningIcon } alt="" className="warning-icon" />
							<h2>
								{ storageOverlimit && __( 'Over storage space', 'jetpack-backup-pkg' ) }
								{ ! storageOverlimit && __( 'Out of storage space', 'jetpack-backup-pkg' ) }
							</h2>
						</div>
						<h1>{ __( 'Backups stopped', 'jetpack-backup-pkg' ) }</h1>
					</>
				) }

				{ stats.warnings && ! backupsStopped && (
					<div className="backup__warning-text">
						{ createInterpolateElement(
							__(
								'Backup is completed with some files missing. See your <a>backup in the cloud</a> for more details.',
								'jetpack-backup-pkg'
							),
							{
								a: (
									<a
										href={ getRedirectUrl( 'jetpack-backup', { site: domain } ) }
										target="_blank"
										rel="noreferrer"
									/>
								),
							}
						) }
					</div>
				) }
				{ ! stats.warnings &&
					! backupsStopped &&
					createInterpolateElement(
						__(
							'<Button>See backups in the cloud</Button><br/><ExternalLink>Or view your most recent restore point</ExternalLink>',
							'jetpack-backup-pkg'
						),
						{
							Button: (
								<a
									className="button"
									href={ getRedirectUrl( 'jetpack-backup', { site: domain } ) }
									onClick={ trackSeeBackupsCtaClick }
									target="_blank"
									rel="noreferrer"
								/>
							),
							br: <br />,
							ExternalLink: (
								<ExternalLink
									className="backup__restore-point-link"
									href={ getRedirectUrl( 'backup-plugin-activity-log', { site: domain } ) }
									onClick={ trackRecentRestorePointClick }
								/>
							),
						}
					) }
				{ ! stats.warnings &&
					backupsStopped &&
					createInterpolateElement(
						__(
							'<Button>Upgrade your storage</Button><br/><a>Or view your most recent backup</a>',
							'jetpack-backup-pkg'
						),
						{
							Button: (
								<a
									className="button"
									href={ getProductCheckoutUrl(
										addonSlug,
										siteSlug,
										`${ adminUrl }admin.php?page=jetpack-backup`,
										true
									) }
									onClick={ trackUpgradeStorageClick }
									target="_blank"
									rel="noreferrer"
								/>
							),
							a: (
								<a
									className="backup__restore-point-link"
									href={ getRedirectUrl( 'jetpack-backup', { site: domain } ) }
									onClick={ trackSeeBackupsCtaClick }
									target="_blank"
									rel="noreferrer"
								/>
							),
							br: <br />,
						}
					) }
			</div>
			<div className="lg-col-span-0 md-col-span-4 sm-col-span-0"></div>
			<div className="lg-col-span-2 md-col-span-2 sm-col-span-2">
				<StatBlock
					icon={ PostsIcon }
					label={ __( 'Posts', 'jetpack-backup-pkg' ) }
					value={ stats.posts }
				/>
			</div>
			<div className="lg-col-span-2 md-col-span-2 sm-col-span-2">
				<StatBlock
					icon={ UploadsIcon }
					label={ __( 'Uploads', 'jetpack-backup-pkg' ) }
					value={ stats.uploads }
				/>
			</div>
			<div className="lg-col-span-2 md-col-span-2 sm-col-span-2">
				<StatBlock
					icon={ PluginsIcon }
					label={ __( 'Plugins', 'jetpack-backup-pkg' ) }
					value={ stats.plugins }
				/>
			</div>
			<div className="lg-col-span-2 md-col-span-2 sm-col-span-2">
				<StatBlock
					icon={ ThemesIcon }
					label={ __( 'Themes', 'jetpack-backup-pkg' ) }
					value={ stats.themes }
				/>
			</div>
		</div>
	);
};

const InProgressBackup = ( { progress, showProgressBar = true } ) => {
	const domain = useSelect( select => select( STORE_ID ).getCalypsoSlug(), [] );
	const siteTitle = useSelect( select => select( STORE_ID ).getSiteTitle(), [] );

	return (
		<div className="jp-row">
			<div className="lg-col-span-5 md-col-span-8 sm-col-span-4">
				{ showProgressBar && (
					<div className="backup__progress">
						<div className="backup__progress-info">
							<p>
								{ sprintf(
									/* translators: placeholder is the Site Title */
									__( 'Backing up %s', 'jetpack-backup-pkg' ),
									siteTitle
								) }
							</p>
							<p className="backup__progress-info-percentage">{ progress }%</p>
						</div>
						<div className="backup__progress-bar">
							<div
								className="backup__progress-bar-actual"
								style={ { width: progress + '%' } }
							></div>
						</div>
					</div>
				) }
				<h1>{ __( 'Your first cloud backup will be ready soon', 'jetpack-backup-pkg' ) }</h1>
				<p>
					{ __(
						'The first backup usually takes a few minutes, so it will become available soon.',
						'jetpack-backup-pkg'
					) }
				</p>
				<p>
					{ createInterpolateElement(
						__(
							'In the meanwhile, you can start getting familiar with your <a>backup management on Jetpack.com</a>.',
							'jetpack-backup-pkg'
						),
						{
							a: (
								<a
									href={ getRedirectUrl( 'jetpack-backup', { site: domain } ) }
									target="_blank"
									rel="noreferrer"
								/>
							),
						}
					) }
				</p>
			</div>
			<div className="lg-col-span-1 md-col-span-4 sm-col-span-0"></div>
			<div className="backup__animation lg-col-span-6 md-col-span-2 sm-col-span-2">
				<img className="backup__animation-el-1" src={ BackupAnim1 } alt="" />
				<img className="backup__animation-el-2" src={ BackupAnim2 } alt="" />
				<img className="backup__animation-el-3" src={ BackupAnim3 } alt="" />
			</div>
		</div>
	);
};

export default Backups;
