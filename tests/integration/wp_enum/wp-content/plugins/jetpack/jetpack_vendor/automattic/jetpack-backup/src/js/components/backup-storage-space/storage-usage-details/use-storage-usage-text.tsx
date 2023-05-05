import { useMemo, createInterpolateElement } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

const StorageUnits = {
	Gigabyte: 2 ** 30,
	Terabyte: 2 ** 40,
};

const getAppropriateStorageUnit = bytes => {
	if ( bytes < StorageUnits.Terabyte ) {
		return StorageUnits.Gigabyte;
	}

	return StorageUnits.Terabyte;
};

const bytesToUnit = ( bytes, unit ) => bytes / unit;

export const useStorageUsageText = ( bytesUsed, bytesAvailable ) => {
	return useMemo( () => {
		if ( bytesUsed === undefined ) {
			return null;
		}

		const usedGigabytes = bytesToUnit( bytesUsed, StorageUnits.Gigabyte );

		if ( bytesAvailable === undefined ) {
			// translators: Must use unit abbreviation; describes an amount of storage space in gigabytes (e.g., 15.4GB used)
			return sprintf( __( '%1$dGB used', 'jetpack-backup-pkg' ), usedGigabytes );
		}

		const availableUnit = getAppropriateStorageUnit( bytesAvailable );
		const availableUnitAmount = bytesToUnit( bytesAvailable, availableUnit );

		if ( availableUnit === StorageUnits.Gigabyte ) {
			return createInterpolateElement(
				// eslint-disable-next-line @wordpress/valid-sprintf
				sprintf(
					// translators: Must use unit abbreviation; describes used vs available storage amounts (e.g., 20.0GB of 30GB used, 0.5GB of 20GB used)
					__( 'Using <strong>%1.1fGB</strong> of %2fGB', 'jetpack-backup-pkg' ),
					usedGigabytes,
					availableUnitAmount
				),
				{
					strong: <strong />,
				}
			);
		}

		return createInterpolateElement(
			sprintf(
				// translators: Must use unit abbreviation; describes used vs available storage amounts (e.g., 20.0GB of 1TB used, 0.5GB of 2TB used)
				__( 'Using <strong>%1$dGB</strong> of %2$dTB', 'jetpack-backup-pkg' ),
				usedGigabytes,
				availableUnitAmount
			),
			{
				strong: <strong />,
			}
		);
	}, [ bytesUsed, bytesAvailable ] );
};
