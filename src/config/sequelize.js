const { Sequelize } = require("sequelize");

const sequelize = new Sequelize("digital_links", "ronierlima", "uYT74kfKhJbF", {
  host: "ep-hidden-lake-004674-pooler.us-east-2.aws.neon.tech",
  dialect: "postgres",
  dialectOptions: {
    ssl: true,
  },
});

module.exports = { sequelize };
