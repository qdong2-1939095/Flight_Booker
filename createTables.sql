-- Stores each user's basic information
CREATE TABLE Users (
    username varchar(20) PRIMARY KEY,
    password varbinary(20),
    balance int,
    salt varbinary(20) -- password verification
);

-- Stores reservations made by the user through the application
CREATE TABLE Reservations (
	rid int,
	username varchar(20),
	direct int,              -- 1 if direct, 0 if indirect
	fid int,
	day int,
	carrier_id varchar(20),
	flight_num varchar(20),
	origin_city varchar(255),
	dest_city varchar(255),
	actual_time int,
	price int,
	capacity int,
	paid int,                -- 1 if paid, 0 if not
	cancelled int            -- 1 if cancelled, 0 if not
);

-- Stores the number of seats already booked in each flight, and the corresponding
-- flight's fid
CREATE TABLE Capacity (
	fid int,
	seats int
);

-- Each time a reservation is made, the tuple updated by increment
CREATE TABLE ID (
	rid int
);