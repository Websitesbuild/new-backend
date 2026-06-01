-- Users table
CREATE TABLE users (
    usr_id BIGSERIAL PRIMARY KEY,
    usr_email VARCHAR NOT NULL,
    usr_password VARCHAR,
    role VARCHAR
);

-- Projects table
CREATE TABLE projects (
    proj_id SERIAL PRIMARY KEY,
    proj_name VARCHAR,
    proj_desc VARCHAR,
    status VARCHAR,
    price VARCHAR,
    material VARCHAR,
    date TIMESTAMP
);

-- Members table
CREATE TABLE members (
    mem_id SERIAL PRIMARY KEY,
    usr_name VARCHAR,
    address VARCHAR,
    phone VARCHAR,
    proj_id INT REFERENCES projects(proj_id)
);

-- Member Projects table
CREATE TABLE member_projects (
    mem_id INT REFERENCES members(mem_id),
    proj_id INT REFERENCES projects(proj_id),
    PRIMARY KEY (mem_id, proj_id)
);

-- Member Payments table
CREATE TABLE member_payments (
    id SERIAL PRIMARY KEY,
    mem_id INT REFERENCES members(mem_id),
    proj_id INT REFERENCES projects(proj_id),
    amount NUMERIC NOT NULL,
    paid_at TIMESTAMP,
    remarks VARCHAR
);

-- Member Piece History table
CREATE TABLE member_piece_history (
    id SERIAL PRIMARY KEY,
    mem_id INT REFERENCES members(mem_id),
    proj_id INT REFERENCES projects(proj_id),
    piece_count INT NOT NULL,
    completed_at TIMESTAMP
);
