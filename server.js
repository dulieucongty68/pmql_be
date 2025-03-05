const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { connectDB, sequelize } = require("./config/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ROLE_NOTE } = require("./enums");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Middleware lấy userId từ token
const extractUserId = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET || "your_secret_key",
    (err, decoded) => {
      if (err) {
        return res.status(403).json({ error: "Forbidden: Invalid token" });
      }
      req.userId = decoded.id;
      next();
    }
  );
};

// API Đăng nhập
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Truy vấn user bằng Raw Query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const existingUser = user[0];

    // Kiểm tra mật khẩu
    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Tạo JWT token
    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Thiết lập cookie
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.json({
      message: "Logged in successfully",
      data: {
        token,
        is_first_login: existingUser.is_first_login,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: "Login failed" });
  }
});

//Logout

app.post("/auth/logout", (req, res) => {
  res.cookie("token", "", {
    expires: new Date(0),
    path: "/",
  });

  return res.json({ message: "Logged out" });
});

// Update password

app.put("/auth/update-password", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Tìm user trong database bằng raw query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const existingUser = user[0];

    // Hash mật khẩu mới
    const hashedPassword = await bcrypt.hash(password, 10);

    // Cập nhật mật khẩu trong database
    await sequelize.query(
      `UPDATE "User" SET password = :hashedPassword, is_first_login = false WHERE username = :username;`,
      {
        replacements: { hashedPassword, username },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Cập nhật cookie mới
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).json({ error: "Failed to update password" });
  }
});

app.post("/auth/update-password", async (req, res) => {
  try {
    const { username, password, newPassword } = req.body;

    // Tìm user trong database bằng raw query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const existingUser = user[0];

    // Hash mật khẩu mới
    const hashedPassword = await bcrypt.hash(password, 10);
    const newHashedPassword = await bcrypt.hash(newPassword, 10);

    // Cập nhật mật khẩu trong database
    await sequelize.query(
      `UPDATE "User" SET password = :newHashedPassword, is_first_login = false WHERE username = :username And password = :hashedPassword;`,
      {
        replacements: { newHashedPassword, hashedPassword, username },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Cập nhật cookie mới
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).json({ error: "Failed to update password" });
  }
});

// Customer
// GET: Lấy danh sách khách hàng (phân trang)
app.get("/customers", extractUserId, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search ? `%${req.query.search}%` : null;
    const order_by = req.query.order_by || null;
    const order_type = req.query.order_type || null;
    const offset = (page - 1) * limit;

    const userId = req.userId;

    // Lấy quyền hạn của user
    const userQuery = `SELECT is_admin, is_team_lead, team_id FROM "User" WHERE id = :userId`;
    const userResult = await sequelize.query(userQuery, {
      replacements: { userId },
      type: sequelize.QueryTypes.SELECT,
    });

    const isAdmin = userResult[0].is_admin;

    const replacements = { limit, offset };
    let searchCondition = "";

    if (search) {
      searchCondition = `AND c.full_name ILIKE :search OR c.phone_number ILIKE :search`;
      replacements.search = search;
    }
    let orderCondition = ``;
    if (order_by && order_type) {
      orderCondition = `ORDER BY ${order_by} ${order_type}`;
    }
    let addFilter = ``;
    if (!isAdmin) {
      addFilter = `AND c.team_id = :team_id`;
      replacements.team_id = userResult[0].team_id;
    }
    const result = await sequelize.query(
      `
      WITH customer_data AS (
        SELECT c.*, 
              CASE 
                WHEN u.is_admin = true THEN 'Quản lý'
                WHEN u.is_team_lead = true THEN 'Tổ trưởng'
                ELSE 'Nhân viên'
              END AS created_by,
              CASE 
                WHEN u2.is_admin = true THEN 'Quản lý'
                WHEN u2.is_team_lead = true THEN 'Tổ trưởng'
                ELSE 'Nhân viên'
              END AS updated_by,
              t.team_name
        FROM "Customer" c
        LEFT JOIN "User" u ON c.created_by = u.id
        LEFT JOIN "User" u2 ON c.updated_by = u2.id
        LEFT JOIN "Team" t ON t.id = c.team_id
        WHERE 1=1 
        ${searchCondition}
        ${addFilter}
        ORDER BY c.created_at DESC
        LIMIT :limit OFFSET :offset
      )
      SELECT CAST((SELECT COUNT(*) FROM "Customer" AS c WHERE 1=1 ${addFilter}) AS INTEGER) AS total, 
            json_agg(customer_data) AS customers 
      FROM customer_data;
      `,
      {
        replacements,
        type: sequelize.QueryTypes.SELECT,
      }
    );

    const { total, customers } = result[0] || { total: 0, customers: [] };

    console.log(customers);

    return res.json({
      data:
        customers?.map((e) => ({
          full_name: e.full_name,
          year_of_birth: e.year_of_birth,
          phone_number: e.phone_number,
          note: e.note,
          role_note: e.role_note,
          status: e.status,
          created_at: e.created_at,
          team_id: e.team_id,
          created_by: e.created_by,
          id: e.id,
          team_name: e.team_name,
        })) || [],
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error fetching customers:", err);
    return res
      .status(500)
      .json({ error: "Error fetching customers", details: err.message });
  }
});

// Customer
// GET: Lấy danh sách khách hàng (phân trang)
app.get("/customers/export", async (req, res) => {
  try {
    const result = await sequelize.query(
      `
      WITH customer_data AS (
        SELECT c.*, 
              CASE 
                WHEN u.is_admin = true THEN 'Quản lý'
                WHEN u.is_team_lead = true THEN 'Tổ trưởng'
                ELSE 'Nhân viên'
              END AS created_by,
              CASE 
                WHEN u2.is_admin = true THEN 'Quản lý'
                WHEN u2.is_team_lead = true THEN 'Tổ trưởng'
                ELSE 'Nhân viên'
              END AS updated_by,
              CASE 
              WHEN c.status = '2' THEN c.updated_at
              ELSE null
              END as updated_at,
              t.team_name
        FROM "Customer" c
        LEFT JOIN "User" u ON c.created_by = u.id
        LEFT JOIN "User" u2 ON c.updated_by = u2.id
        LEFT JOIN "Team" t ON t.id = c.team_id
      )
      SELECT CAST((SELECT COUNT(*) FROM "Customer") AS INTEGER) AS total, 
            json_agg(customer_data) AS customers 
      FROM customer_data;
      `,
      {
        type: sequelize.QueryTypes.SELECT,
      }
    );

    const { total, customers } = result[0] || { total: 0, customers: [] };

    return res.json({
      data:
        customers.map((e) => ({
          full_name: e.full_name,
          year_of_birth: e.year_of_birth,
          phone_number: e.phone_number,
          note: e.note,
          role_note: e.role_note,
          status: e.status,
          created_at: e.created_at,
          team_id: e.team_id,
          created_by: e.created_by,
          id: e.id,
          updated_at: e.updated_at,
          team_name: e.team_name,
        })) || [],
    });
  } catch (err) {
    console.error("Error fetching customers:", err);
    return res
      .status(500)
      .json({ error: "Error fetching customers", details: err.message });
  }
});

// Customer
// GET: Lấy danh sách khách hàng
app.get("/customers/check", extractUserId, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search ? `%${req.query.search}%` : null;
    const offset = (page - 1) * limit;

    const order_by = req.query.order_by || null;
    const order_type = req.query.order_type || null;

    let orderCondition = ``;
    if (order_by && order_type) {
      orderCondition = `, ${order_by} ${order_type}`;
    }

    const replacements = { limit, offset };
    let searchCondition = "";

    if (search) {
      searchCondition = `AND c.full_name ILIKE :search OR c.phone_number ILIKE :search`;
      replacements.search = search;
    }

    const userId = req.userId;

    // Lấy quyền hạn của user
    const userQuery = `SELECT is_admin, is_team_lead, team_id FROM "User" WHERE id = :userId`;
    const userResult = await sequelize.query(userQuery, {
      replacements: { userId },
      type: sequelize.QueryTypes.SELECT,
    });

    const isAdmin = userResult[0].is_admin;
    let joinTeam = ``;
    if (!isAdmin) {
      joinTeam = `AND c.team_id = :team_id`;
      replacements.team_id = userResult[0].team_id;
    }

    const result = await sequelize.query(
      `
      WITH customer_data AS (
        SELECT c.*, 
              u.username AS created_by,
              CASE 
                  WHEN u.is_admin = true THEN 'Quản lý'
                  WHEN u.is_team_lead = true THEN 'Tổ trưởng'
                  ELSE 'Nhân viên'
              END AS created_role,
              u2.username AS updated_by,
              CASE 
                  WHEN u2.is_admin = true THEN 'Quản lý'
                  WHEN u2.is_team_lead = true THEN 'Tổ trưởng'
                  ELSE 'Nhân viên'
              END AS updated_role,
              t.team_name
        FROM "Customer" c
        LEFT JOIN "User" u ON c.created_by = u.id
        LEFT JOIN "User" u2 ON c.updated_by = u2.id
        LEFT JOIN "Team" t ON t.id = c.team_id
        WHERE 1=1
        ${searchCondition}
        ORDER BY c.created_at DESC
        LIMIT :limit OFFSET :offset
)
SELECT CAST((SELECT COUNT(*) 
             FROM "Customer" c ) AS INTEGER) AS total, 
       json_agg(customer_data) AS customers
FROM customer_data;

      `,
      {
        replacements,
        type: sequelize.QueryTypes.SELECT,
      }
    );

    const { total, customers } = result[0] || { total: 0, customers: [] };

    return res.json({
      data: customers || [],
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error fetching customers:", err);
    return res
      .status(500)
      .json({ error: "Error fetching customers", details: err.message });
  }
});

// PUT: Cập nhật khách hàng
app.put("/customers/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      full_name,
      year_of_birth,
      phone_number,
      note,
      role_note,
      status,
      team_id,
      updated_by,
    } = req.body;

    if (!id) {
      return res.status(400).json({ error: "Customer ID is required" });
    }

    if (!updated_by) {
      return res.status(400).json({ error: "Updated by is required" });
    }

    // Kiểm tra khách hàng có tồn tại không
    const existingCustomer = await sequelize.query(
      `SELECT * FROM "Customer" WHERE id = :id LIMIT 1`,
      {
        replacements: { id },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (existingCustomer.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    // Cập nhật thông tin khách hàng
    await sequelize.query(
      `UPDATE "Customer" 
       SET full_name = :full_name, 
           year_of_birth = :year_of_birth, 
           phone_number = :phone_number, 
           note = :note, 
           role_note = :role_note, 
           status = :status, 
           team_id = :team_id, 
           updated_by = :updated_by, 
           updated_at = NOW()
       WHERE id = :id`,
      {
        replacements: {
          id,
          full_name,
          year_of_birth,
          phone_number,
          note,
          role_note,
          status,
          team_id,
          updated_by,
        },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    return res.json({ message: "Customer updated successfully" });
  } catch (error) {
    console.error("Error updating customer:", error);
    return res.status(500).json({ error: "Failed to update customer" });
  }
});

// POST: Tạo khách hàng mới
app.post("/customers", async (req, res) => {
  try {
    const {
      full_name,
      year_of_birth,
      phone_number,
      note,
      role_note,
      status,
      team_id,
      updated_by,
      created_at,
    } = req.body;

    if (!phone_number) {
      return res.status(400).json({ error: "Phone number is required" });
    }

    // Kiểm tra số điện thoại đã tồn tại chưa
    const existingCustomer = await sequelize.query(
      `SELECT * FROM "Customer" WHERE phone_number = :phone_number LIMIT 1`,
      {
        replacements: { phone_number },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (existingCustomer.length > 0) {
      return res.status(400).json({ error: "Phone number already exists" });
    }

    // Thêm khách hàng mới
    await sequelize.query(
      `
      INSERT INTO "Customer" (
        full_name, year_of_birth, phone_number, note, role_note, 
        status, team_id, created_by, created_at, updated_by, updated_at
      ) 
      VALUES (
        :full_name, :year_of_birth, :phone_number, :note, :role_note,
        :status, :team_id, :updated_by, :created_at, :updated_by, NOW()
      )
      `,
      {
        replacements: {
          full_name,
          year_of_birth,
          phone_number,
          note,
          role_note,
          status,
          team_id,
          created_at,
          updated_by,
        },
        type: sequelize.QueryTypes.INSERT,
      }
    );

    return res.status(201).json({ message: "Customer Created Successfully" });
  } catch (error) {
    console.error("Error creating customer:", error);
    return res.status(500).json({ error: "Failed to create customer" });
  }
});
// PUT: Cập nhật trạng thái khách hàng
app.put("/customers", extractUserId, async (req, res) => {
  try {
    const {
      full_name,
      year_of_birth,
      phone_number,
      note,
      role_note,
      status,
      team_id,
      updated_by,
      id,
      updated_at,
    } = req.body;
    const userId = req.userId;

    if (!id || status === undefined || !updated_by) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let updatedByInt = parseInt(updated_by, 10);
    const statusInt = parseInt(status, 10);

    if (isNaN(updatedByInt) || isNaN(statusInt)) {
      return res
        .status(400)
        .json({ error: "Invalid updated_by or status value" });
    }

    // Lấy quyền hạn của user
    const userQuery = `SELECT is_admin, is_team_lead FROM "User" WHERE id = :userId`;
    const userResult = await sequelize.query(userQuery, {
      replacements: { userId },
      type: sequelize.QueryTypes.SELECT,
    });

    if (!userResult.length) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const isAdmin = userResult[0].is_admin;
    const isTeamLead = userResult[0].is_team_lead;

    // Lấy trạng thái hiện tại của khách hàng
    const currentStatusResult = await sequelize.query(
      `SELECT status FROM "Customer" WHERE id = :id`,
      {
        replacements: { id },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!currentStatusResult.length) {
      return res.status(404).json({ error: "Customer not found" });
    }

    const currentStatus = parseInt(currentStatusResult[0].status, 10);

    // Nếu trạng thái hiện tại là 2, không cần updated_by
    if (currentStatus === 2) {
      updatedByInt = null;
    }

    // Kiểm tra quyền cập nhật trạng thái
    if (!isAdmin && !isTeamLead && currentStatus === 2) {
      return res
        .status(403)
        .json({ error: "Only Admin or Team Lead can update when status is 2" });
    }

    // Kiểm tra điều kiện cập nhật trạng thái hợp lệ
    const validTransitions = {
      0: [1, 2], // 0 → 1 hoặc 0 → 2
      1: [2], // 1 → 2
      2: [1], // 2 → 1 (chỉ Admin hoặc Team Lead)
    };

    console.log(currentStatus);

    console.log(statusInt);

    if (currentStatus === 2 && statusInt === 1 && !isAdmin && !isTeamLead) {
      return res
        .status(403)
        .json({ error: "Only Admin or Team Lead can reactivate a customer" });
    }

    // if (!validTransitions[currentStatus]?.includes(statusInt)) {
    //   return res.status(400).json({ error: "Invalid status transition" });
    // }

    // Cập nhật trạng thái khách hàng
    await sequelize.query(
      `UPDATE "Customer" 
       SET 
       full_name =:full_name
       , year_of_birth = :year_of_birth
       , note = :note
       , role_note = :role_note
       , team_id = :team_id
       , status = :status
       , updated_by = :updatedByInt
       , updated_at = :updated_at
       WHERE id = :id`,
      {
        replacements: {
          full_name,
          year_of_birth,
          phone_number,
          note,
          role_note,
          status,
          team_id,
          updatedByInt,
          updated_at,
          id,
        },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    return res.json({ message: "Status updated successfully" });
  } catch (err) {
    console.error("Error updating status:", err.stack);
    return res.status(500).json({ error: "Error updating status" });
  }
});

// DELETE: Xóa khách hàng theo ID
app.delete("/customers/:id", extractUserId, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: "Missing customer ID" });
    }

    const userId = req.userId;

    // Lấy thông tin user hiện tại
    const userQuery = `SELECT is_admin, team_id FROM "User" WHERE id = :userId`;
    const userInfo = await sequelize.query(userQuery, {
      type: sequelize.QueryTypes.SELECT,
      replacements: { userId },
    });

    const isAdmin = userInfo[0].is_admin;

    if (!isAdmin) {
      // Lấy thông tin user hiện tại
      const checkUserStatus = `SELECT status FROM "Customer" WHERE id = :id`;
      const checkUserStatusInfo = await sequelize.query(checkUserStatus, {
        type: sequelize.QueryTypes.SELECT,
        replacements: { id },
      });
      const userStatus = checkUserStatusInfo[0]?.status;
      if (userStatus === "2") {
        console.log("HERE");
        return res
          .status(400)
          .json({ error: "Không thể xoá khách hàng này !" });
      }
    }

    await sequelize.query(`DELETE FROM "Customer" WHERE id = :id`, {
      replacements: { id },
      type: sequelize.QueryTypes.DELETE,
    });

    return res.json({ message: "Customer deleted successfully" });
  } catch (err) {
    console.error("Error deleting customer:", err.stack);
    return res.status(500).json({ error: "Internal server error" });
  }
});

//

/**
 * PUT /api/users
 * Tạo nhân viên mới
 */
app.put("/users", async (req, res) => {
  try {
    const { id } = req.body;

    if (!id) {
      return res
        .status(400)
        .json({ error: "Username, name, and team_id are required" });
    }

    // Lấy trạng thái hiện tại của khách hàng
    const [userById] = await sequelize.query(
      `SELECT username FROM "User" WHERE id = :id LIMIT 1`,
      {
        replacements: { id: Number(id) },
        type: sequelize.QueryTypes.SELECT,
      }
    );
    const username = userById.username;
    const hashedPassword = await bcrypt.hash(username, 10);
    const query = `
      UPDATE "User"
      SET password = :password  
      WHERE username = :username;
    `;

    await sequelize.query(query, {
      replacements: {
        username,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      message: "User reset password successfully",
    });
  } catch (err) {
    console.error("Error reset user:", err);
    res.status(500).json({ error: "Failed to reset user" });
  }
});

app.get("/employees", extractUserId, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const userId = req.userId;

    // Lấy thông tin user hiện tại
    const userQuery = `SELECT is_admin, team_id FROM "User" WHERE id = :userId`;
    const userInfo = await sequelize.query(userQuery, {
      type: sequelize.QueryTypes.SELECT,
      replacements: { userId },
    });

    if (!userInfo.length) {
      return res.status(404).json({ error: "User not found" });
    }

    const { is_admin, team_id } = userInfo[0];

    let condition = `WHERE u.is_admin = false`; // Luôn loại bỏ admin khỏi danh sách
    let replacements = { limit, offset };

    if (!is_admin) {
      // Nếu không phải admin, chỉ lấy nhân viên trong team của mình
      condition += ` AND u.team_id = :team_id`;
      replacements.team_id = team_id;
    }

    const query = `
      WITH user_data AS (
        SELECT u.id, u.name, u.username, u.team_id, u.status, u.is_team_lead, 
               c.username AS created_by_username, 
               u2.username AS updated_by_username
        FROM "User" AS u
        LEFT JOIN "User" c ON u.created_by = c.id
        LEFT JOIN "User" u2 ON u.updated_by = u2.id
        ${condition}
        ORDER BY u.is_team_lead DESC, u.team_id ASC, u.id ASC
        LIMIT :limit OFFSET :offset
      )
      SELECT CAST((SELECT COUNT(*) FROM "User" u ${condition}) AS INTEGER) AS total, 
             json_agg(user_data) AS users 
      FROM user_data;
    `;

    const result = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
      replacements,
    });

    const { total, users } = result[0] || { total: 0, users: [] };

    res.json({
      data: users,
      total: Number(total),
      page,
      totalPages: Math.ceil(Number(total) / limit),
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res
      .status(500)
      .json({ error: "Error fetching users", details: err.message });
  }
});

/**
 * POST /api/employees
 * Tạo nhân viên mới
 */
app.post("/employees", async (req, res) => {
  try {
    const { username, name, user_role, status, team_id } = req.body;

    if (!username || !name || !team_id) {
      return res
        .status(400)
        .json({ error: "Username, name, and team_id are required" });
    }

    const hashedPassword = await bcrypt.hash(username, 10);
    const isAdmin = user_role === "0";
    const isTeamLead = user_role === "1";
    const teamIdAsInt = parseInt(team_id, 10);

    if (isNaN(teamIdAsInt)) {
      return res
        .status(400)
        .json({ error: "Invalid team_id, it must be an integer" });
    }

    const query = `
      INSERT INTO "User" 
      (username, name, password, is_admin, is_team_lead, is_first_login, status, team_id, updated_at)
      VALUES 
      (:username, :name, :password, :isAdmin, :isTeamLead, true, :status, :teamId, NOW())
    `;

    await sequelize.query(query, {
      replacements: {
        username,
        name,
        password: hashedPassword,
        isAdmin,
        isTeamLead,
        status: status || "1",
        teamId: teamIdAsInt,
      },
    });

    res.status(201).json({
      message: "User created successfully",
      data: { username, name, team_id: teamIdAsInt },
    });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ error: "Failed to create user" });
  }
});

/**
 * PUT /api/employees
 * Reset mật khẩu nhân viên
 */
app.put("/employees/reset", async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const checkUserQuery = `SELECT COUNT(*)::int AS count, username FROM "User" WHERE id = :id GROUP BY username`;
    const userExists = await sequelize.query(checkUserQuery, {
      replacements: { id },
      type: sequelize.QueryTypes.SELECT,
    });

    if (!userExists[0]?.count) {
      return res.status(404).json({ error: "User not found" });
    }
    const username = userExists[0]?.username;
    const hashedPassword = await bcrypt.hash(username, 10);
    const resetQuery = `UPDATE "User" SET password = :hashedPassword, is_first_login = TRUE WHERE id = :id`;
    await sequelize.query(resetQuery, { replacements: { hashedPassword, id } });

    res.json({ message: "Reset password successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});
/**
 * PUT /api/employees/:id
 * Cập nhật thông tin nhân viên (Chỉ admin hoặc chính nhân viên mới có quyền)
 */
app.put("/employees", extractUserId, async (req, res) => {
  try {
    const { id, name, username, password, team_id, status, is_first_login } =
      req.body;
    const userId = req.userId;

    // Kiểm tra ID hợp lệ
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: "Invalid User ID" });
    }

    // Kiểm tra user có tồn tại không
    const userCheckQuery = `SELECT id, is_admin FROM "User" WHERE id = :id`;
    const userCheck = await sequelize.query(userCheckQuery, {
      replacements: { id },
      type: sequelize.QueryTypes.SELECT,
    });

    if (!userCheck.length) {
      return res.status(404).json({ error: "User not found" });
    }

    // Kiểm tra quyền hạn: Chỉ admin hoặc chính nhân viên mới có thể chỉnh sửa
    const adminCheckQuery = `SELECT is_admin, is_team_lead FROM "User" WHERE id = :userId`;
    const adminCheck = await sequelize.query(adminCheckQuery, {
      replacements: { userId },
      type: sequelize.QueryTypes.SELECT,
    });

    const isAdmin = adminCheck[0]?.is_admin;
    const isTeamLead = adminCheck[0]?.is_team_lead;

    if (!isAdmin && !isTeamLead && parseInt(userId) !== parseInt(id)) {
      return res
        .status(403)
        .json({ error: "You are not authorized to update this user" });
    }

    // Xây dựng câu lệnh UPDATE động dựa trên các trường được gửi
    let updateFields = [];
    let replacements = { id, updated_by: userId };

    if (name) {
      updateFields.push(`name = :name`);
      replacements.name = name;
    }
    if (username) {
      updateFields.push(`username = :username`);
      replacements.username = username;
    }
    if (password) {
      updateFields.push(`password = :password`);
      replacements.password = password;
    }
    if (team_id) {
      updateFields.push(`team_id = :team_id`);
      replacements.team_id = team_id;
    }
    if (status) {
      updateFields.push(`status = :status`);
      replacements.status = status;
    }
    if (is_first_login) {
      updateFields.push(`is_first_login = :is_first_login`);
      replacements.is_first_login = is_first_login;
    }
    if (updateFields.length === 0) {
      return res.status(400).json({ error: "No valid fields to update" });
    }

    const updateQuery = `
      UPDATE "User"
      SET ${updateFields.join(
        ", "
      )}, updated_at = NOW(), updated_by = :updated_by
      WHERE id = :id
    `;

    await sequelize.query(updateQuery, { replacements });

    res.json({ message: "User updated successfully", updated_by: userId });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Failed to update user" });
  }
});
//

/**
 * GET /api/statistical
 * Lấy thống kê cuộc gọi theo team và role_note
 */
app.get("/statistical", async (req, res) => {
  try {
    const { role_note } = req.query;
    const normalizedRoleNote = role_note.trim();

    let whereClause = "";
    const replacements = {};

    if (
      normalizedRoleNote &&
      normalizedRoleNote.length > 0 &&
      normalizedRoleNote !== "null"
    ) {
      whereClause = `AND c.role_note =  :role_note`;
      replacements.role_note = ROLE_NOTE.find(
        (item) => item.label === normalizedRoleNote
      )?.key;
    }
    const query = `
      SELECT COUNT(1) AS call_count, 
       CASE 
        WHEN c.role_note = '0' THEN '0'
        WHEN c.role_note = '1' THEN 'CV'
        WHEN c.role_note = '2' THEN 'APP'
        WHEN c.role_note = '3' THEN 'DD'
        WHEN c.role_note = '4' THEN 'AD'
       ELSE '0'
       END AS caller, 
       t.team_name
      FROM "Customer" AS c
      INNER JOIN "Team" AS t ON c.team_id = t.id
      WHERE c.status = '2' OR c.status = '0'
      AND DATE_TRUNC('month', c.updated_at) = DATE_TRUNC('month', NOW())
      ${whereClause}
      GROUP BY c.team_id, c.role_note, t.team_name
      ORDER BY call_count DESC;
    `;

    const callCounts = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
      replacements,
    });
    console.log(callCounts);

    const formattedCallCounts = callCounts.map(
      ({ caller, call_count, ...rest }) => ({
        ...rest,
        caller: ROLE_NOTE.find(({ key }) => key === caller)?.label || caller,
        call_count: Number(call_count), // Đảm bảo chuyển đổi số
      })
    );

    res.json({ data: formattedCallCounts });
  } catch (err) {
    console.error("Error fetching call counts:", err);
    res.status(500).json({ error: "Error fetching call counts" });
  }
});

//
/**
 * GET /api/teams
 * Lấy danh sách team của user (có hỗ trợ phân trang)
 */
app.get("/teams", extractUserId, async (req, res) => {
  try {
    const { page, limit } = req.query;
    const pageNum = Math.max(parseInt(page, 10), 1); // Page mặc định là 1
    const limitNum = Math.max(parseInt(limit, 10), 1); // Limit mặc định là 10
    const offset = (pageNum - 1) * limitNum;
    const userId = req.userId;

    console.log(`User ID from token: ${userId}`);

    // Query lấy danh sách team của user (hỗ trợ admin xem tất cả teams)
    const teamsQuery = `
      WITH user_team AS (
          SELECT team_id, is_admin 
          FROM "User" 
          WHERE id = :userId
      )
      SELECT t.*, 
            u.username AS created_by, 
            u2.username AS updated_by
      FROM "Team" t
      INNER JOIN user_team ut 
      ON (ut.is_admin = true OR t.id = ut.team_id)
      LEFT JOIN "User" u ON t.created_by = u.id
      LEFT JOIN "User" u2 ON t.updated_by = u2.id
      ORDER BY t.created_at ASC, t.team_name ASC, t.id ASC
      ${page && limit ? `LIMIT :limitNum OFFSET :offset` : ``} 
    `;

    const teams = await sequelize.query(teamsQuery, {
      type: sequelize.QueryTypes.SELECT,
      replacements: { userId, limitNum, offset },
    });

    // Query đếm tổng số teams của user (bao gồm trường hợp admin)
    const countQuery = `
      WITH user_team AS (
          SELECT team_id, is_admin 
          FROM "User" 
          WHERE id = :userId
      )
      SELECT COUNT(*)::int AS total 
      FROM "Team" t
      INNER JOIN user_team ut 
      ON (ut.is_admin = true OR t.id = ut.team_id)
    `;

    const countResult = await sequelize.query(countQuery, {
      type: sequelize.QueryTypes.SELECT,
      replacements: { userId },
    });
    const total = countResult[0]?.total || 0;

    return res.json({
      data: teams,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    console.error("Error fetching teams:", err);
    res.status(500).json({ error: "Error fetching teams" });
  }
});

/**
 * POST /api/team
 * Thêm mới một team
 */
app.post("/teams", async (req, res) => {
  try {
    const { team_name } = req.body;
    if (!team_name || typeof team_name !== "string") {
      return res.status(400).json({ error: "Team name is required" });
    }

    // Kiểm tra xem team đã tồn tại chưa
    const existingTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE team_name = :team_name LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { team_name },
      }
    );

    if (existingTeam.length > 0) {
      return res.status(400).json({ error: "Team name already exists" });
    }

    // Tạo team mới
    await sequelize.query(
      `INSERT INTO "Team" (team_name, updated_at) VALUES (:team_name, NOW())`,
      {
        type: sequelize.QueryTypes.INSERT,
        replacements: { team_name },
      }
    );

    return res.status(201).json({
      message: "Tạo tổ thành công",
      data: { team_name },
    });
  } catch (error) {
    console.error("Error creating team:", error);
    res.status(500).json({ error: "Failed to create team" });
  }
});

/**
 * PUT /api/team/:id
 * Cập nhật thông tin team theo ID
 */
app.put("/teams/:id", async (req, res) => {
  try {
    const teamId = parseInt(req.params.id, 10);
    const { team_name, updated_by } = req.body; // `updated_by` là user cập nhật team

    if (!teamId || isNaN(teamId)) {
      return res.status(400).json({ error: "Invalid team ID" });
    }

    if (!team_name || typeof team_name !== "string") {
      return res.status(400).json({ error: "Team name is required" });
    }

    // Kiểm tra xem team có tồn tại không
    const existingTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE id = :teamId LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { teamId },
      }
    );

    if (existingTeam.length === 0) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Kiểm tra xem tên team mới đã tồn tại chưa (tránh trùng lặp)
    const duplicateTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE team_name = :team_name AND id != :teamId LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { team_name, teamId },
      }
    );

    if (duplicateTeam.length > 0) {
      return res.status(400).json({ error: "Team name already exists" });
    }

    // Cập nhật team
    await sequelize.query(
      `
      UPDATE "Team"
      SET team_name = :team_name,
          updated_at = NOW(),
          updated_by = :updated_by
      WHERE id = :teamId
      `,
      {
        type: sequelize.QueryTypes.UPDATE,
        replacements: { team_name, updated_by, teamId },
      }
    );

    return res.json({
      message: "Cập nhật team thành công",
      data: { id: teamId, team_name, updated_by },
    });
  } catch (error) {
    console.error("Error updating team:", error);
    res.status(500).json({ error: "Failed to update team" });
  }
});

// Kết nối database và chạy server
const PORT = process.env.PORT || 5000;
connectDB().then(() => {
  app.listen(PORT, async () => {
    console.log(`🚀 Server is running on port ${PORT}`);
  });
});
