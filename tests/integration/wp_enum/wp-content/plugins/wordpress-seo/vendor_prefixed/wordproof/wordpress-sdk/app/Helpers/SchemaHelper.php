<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class SchemaHelper
{
    /**
     * Builds an blockchain transaction schema object as array.
     *
     * @param object $response The response by WordProof.
     * @return array The blockchain transaction in the correct schema format.
     */
    public static function getBlockchainTransaction($response)
    {
        $postId = $response->uid;
        $hashLink = \YoastSEO_Vendor\WordProof\SDK\Helpers\RestApiHelper::getRestRoute('hashInput', [$postId, $response->hash]);
        $identifier = null;
        if (isset($response->transaction)) {
            $transaction = $response->transaction;
            if (isset($transaction->transactionId)) {
                $identifier = $transaction->transactionId;
            }
            if (isset($transaction->tx)) {
                $identifier = $transaction->tx;
            }
        }
        return ['@type' => 'BlockchainTransaction', 'identifier' => $identifier, 'hash' => $response->hash, 'hashLink' => $hashLink, 'recordedIn' => ['@type' => 'Blockchain', 'name' => $response->transaction->blockchain]];
    }
    /**
     * Retrieves the schema as array for a post.
     *
     * @param integer $postId The post id for which the schema should be returned.
     * @return array The schema as array.
     */
    public static function getSchema($postId)
    {
        $transactions = \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::get($postId, '_wordproof_blockchain_transaction', \false);
        $latest = \array_pop($transactions);
        if (\count($transactions) === 0) {
            return ['timestamp' => $latest];
        }
        return ['timestamp' => \array_merge($latest, ['revisions' => \array_reverse($transactions)])];
    }
}
