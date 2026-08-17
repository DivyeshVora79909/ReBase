async function withTransaction(db, callback) {
  if (!db || typeof db.beginTransaction !== "function") {
    const error = new Error(
      "Transactional writes require a SurrealDB client with beginTransaction() support",
    );
    error.code = "SURREAL_TRANSACTIONS_UNSUPPORTED";
    throw error;
  }
  let transaction;
  try {
    transaction = await db.beginTransaction();
    const result = await callback(transaction);
    await transaction.commit();
    transaction = null;
    return result;
  } catch (error) {
    if (transaction) {
      try {
        await transaction.cancel();
      } catch (cancelError) {
        if (error && typeof error === "object") {
          error.transactionCancelError = cancelError;
        }
      }
    }
    throw error;
  }
}

module.exports = { withTransaction };
