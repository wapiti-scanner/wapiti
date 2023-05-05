import { useMemo } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { StorageUsageLevels } from '../storage-usage-levels';

const useStorageStatusText = ( usageLevel, daysOfBackupsSaved, minDaysOfBackupsAllowed ) => {
	return useMemo( () => {
		switch ( usageLevel ) {
			case StorageUsageLevels.Warning:
				return __(
					'You are close to reaching your storage limit. Once you do, we will delete your oldest backups to make space for new ones.',
					'jetpack-backup-pkg'
				);
			case StorageUsageLevels.Critical:
				return __(
					'You are very close to reaching your storage limit. Once you do, we will delete your oldest backups to make space for new ones.',
					'jetpack-backup-pkg'
				);
			case StorageUsageLevels.Full:
				return sprintf(
					/* translators: %s is a number greather than 0 that means a number of days. */
					__(
						'You have reached your storage limit with %s day(s) of backups saved. Backups have been stopped. Please upgrade your storage to resume backups.',
						'jetpack-backup-pkg'
					),
					daysOfBackupsSaved
				);
			case StorageUsageLevels.BackupsDiscarded:
				return sprintf(
					/* translators: %s is a number greather than 0 that means a number of days. */
					__(
						'We removed your oldest backup(s) to make space for new ones. We will continue to remove old backups as needed, up to the last %s days.',
						'jetpack-backup-pkg'
					),
					minDaysOfBackupsAllowed
				);
		}

		return null;
	}, [ usageLevel, daysOfBackupsSaved, minDaysOfBackupsAllowed ] );
};

export default useStorageStatusText;
