import { AppDataSource } from "../data-source";
import { createDefaultSuperAdmin } from "../init/defaultSuperAdmin";

async function run() {
    await AppDataSource.initialize();

    const email = process.argv[2];

    if (!email) {
        throw new Error("Usage: npm run seed:superadmin admin@email.com");
    }

    await createDefaultSuperAdmin(email);

    process.exit(0);
}

run();