import ProgressBar from '@automattic/components/dist/esm/progress-bar';
import { StorageUsageLevels } from '../storage-usage-levels';
import './style.scss';

const StorageMeter = ( { storageUsed, storageLimit, usageLevel } ) => {
	const STORAGE_METER_CLASS_NAMES = {
		[ StorageUsageLevels.Full ]: 'full-warning',
		[ StorageUsageLevels.Critical ]: 'red-warning',
		[ StorageUsageLevels.Warning ]: 'yellow-warning',
		[ StorageUsageLevels.Normal ]: 'no-warning',
		[ StorageUsageLevels.BackupsDiscarded ]: 'full-warning',
	};
	return (
		<>
			<div className="backup-storage-space__progress-bar">
				<ProgressBar
					className={ STORAGE_METER_CLASS_NAMES[ usageLevel ] }
					value={ storageUsed ?? 0 }
					total={ storageLimit ?? Infinity }
					canGoBackwards={ true }
				/>
			</div>
		</>
	);
};

export default StorageMeter;
