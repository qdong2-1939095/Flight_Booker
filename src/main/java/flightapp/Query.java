package flightapp;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.util.*;

/**
 * Runs queries against a back-end database
 */
public class Query extends QueryAbstract {
  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;
  private PreparedStatement clearTablesStatement;
  private PreparedStatement checkUsernameIsLegalStatement;
  private PreparedStatement getSaltAndHashStatement;
  private PreparedStatement createAccountStatement;
  private PreparedStatement getDirectFlightsStatement;
  private PreparedStatement getIndirectFlightsStatement;
  private PreparedStatement rOnSameDayStatement;
  private PreparedStatement checkCapacityExistStatement;
  private PreparedStatement updateCapacityStatement;
  private PreparedStatement addNewCapacityStatement;
  private PreparedStatement getNumBookedSeatsStatement;
  private PreparedStatement addIDStatement;
  private PreparedStatement addReservationStatement;
  private PreparedStatement updateID;
  private PreparedStatement getIDStatement;
  private PreparedStatement countIDStatement;
  private PreparedStatement checkUnpaidReservationStatement;
  private PreparedStatement getBalanceStatement;
  private PreparedStatement getReservationPriceStatement;
  private PreparedStatement payForReservationStatement;
  private PreparedStatement updateBalanceStatement;
  private PreparedStatement checkHasReservationStatement;
  private PreparedStatement getReservationsStatement;
  private PreparedStatement checkPaidReservationStatement;
  private PreparedStatement cancelReservationStatement;
  private PreparedStatement getCancelledFlightsStatement;



  private boolean logIn;
  private String username;
  private Map<Integer, List<Flight>> itinerarys;

  private static final String CLEAR_TABLES = "DELETE FROM Users; DELETE FROM Reservations; " +
          "DELETE FROM Capacity; DELETE FROM ID;";
  private static final String CHECK_USERNAME = "SELECT COUNT(*) FROM Users WHERE username = ?";
  private static final String GET_SALT_AND_HASH = "SELECT password, salt FROM Users WHERE username = ?";
  private static final String CREATE_ACCOUNT = "INSERT INTO Users VALUES (?, ?, ?, ?)";
  private static final String GET_DIRECT_FLIGHTS = "SELECT TOP (?) fid AS fid, day_of_month AS day_of_month, "
          + "carrier_id AS carrier_id, flight_num AS flight_num, origin_city AS origin_city, " +
          "dest_city AS dest_city, actual_time AS actual_time, capacity AS capacity, price AS price " +
          "FROM Flights " +
          "WHERE origin_city = ? AND dest_city = ? AND day_of_month = ? " +
          "AND canceled = 0" +
          "ORDER BY actual_time, fid";
  private static final String GET_INDIRECT_FLIGHTS = "SELECT TOP (?) F1.fid AS f1_fid, F1.day_of_month AS " +
          "f1_day_of_month, F1.carrier_id AS f1_carrier_id, " +
          "F1.flight_num AS f1_flight_num, F1.origin_city AS f1_origin_city, F1.dest_city AS f1_dest_city, " +
          "F1.actual_time AS f1_actual_time, F1.capacity AS f1_capacity, F1.price AS f1_price, " +
          "F2.fid AS f2_fid, F2.day_of_month AS f2_day_of_month, F2.carrier_id AS f2_carrier_id, " +
          "F2.flight_num AS f2_flight_num, F2.origin_city AS f2_origin_city, F2.dest_city AS f2_dest_city, " +
          "F2.actual_time AS f2_actual_time, F2.capacity AS f2_capacity, F2.price AS f2_price, " +
          "(F1.actual_time + F2.actual_time) AS actual_time, (F1.price + F2.price) AS totalPrice " +
          "FROM FLIGHTS AS F1, FLIGHTS AS F2 " +
          "WHERE F1.dest_city = F2.origin_city AND F1.origin_city = ? AND F2.dest_city = ? AND " +
          "F1.day_of_month = F2.day_of_month AND F1.day_of_month = ? AND F1.canceled = 0 AND F2.canceled = 0 " +
          "ORDER BY actual_time, F1.fid, f2.fid ";
  static final String RESERVATIONS_ON_SAME_DAY = "SELECT COUNT(*) FROM reservations WHERE day = ? AND username = ? " +
          "AND cancelled = 0";
  private static final String CAPACITY_EXISTS = "SELECT COUNT(*) FROM Capacity WHERE fid = ?";
  private static final String UPDATE_CAPACITY = "UPDATE Capacity SET seats = seats + ? WHERE fid = ?";
  private static final String ADD_NEW_CAPACITY = "INSERT INTO Capacity VALUES (?, 1)";
  private static final String GET_NUM_BOOKED_SEATS = "SELECT seats FROM Capacity WHERE fid = ?";
  private static final String ADD_ID = "INSERT INTO ID VALUES(1)";
  private static final String ADD_RESERVATION = "INSERT INTO Reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  private static final String UPDATE_ID = "UPDATE ID SET rid = rid + 1";
  private static final String GET_ID = "SELECT rid from ID";
  private static final String COUNT_ID = "SELECT COUNT(*) FROM ID";
  private static final String CHECK_UNPAID_RESERVATION = "SELECT COUNT(*), username FROM Reservations " +
          "WHERE rid = ? AND paid = 0 AND cancelled = 0" +
          "GROUP BY username HAVING username = ?";
  private static final String GET_BALANCE = "SELECT balance FROM Users WHERE username = ?";
  private static final String GET_RESERVATION_PRICE = "SELECT price FROM Reservations WHERE rid = ? AND username = ?";
  private static final String PAY_FOR_RESERVATION = "UPDATE Reservations SET paid = 1 WHERE rid = ?";
  private static final String UPDATE_BALANCE = "UPDATE Users SET balance = balance + ? WHERE username = ?";
  private static final String CHECK_HAS_RESERVATION = "SELECT COUNT(*) FROM Reservations WHERE username = ? AND cancelled = 0";
  private static final String GET_RESERVATIONS = "SELECT rid, fid, day, carrier_id, flight_num, origin_city, " +
          "dest_city, actual_time, capacity, price, paid, direct FROM Reservations " +
          "WHERE username = ? AND cancelled = 0";
  private static final String CHECK_PAID_RESERVATION = "SELECT COUNT(*), username FROM Reservations " +
          "WHERE rid = ? AND paid = 1 AND cancelled = 0" +
          "GROUP BY username HAVING username = ?";
  private static final String CANCEL_RESERVATION = "UPDATE Reservations SET cancelled = 1 WHERE rid = ?";
  private static final String GET_CANCELLED_FLIGHTS = "SELECT fid FROM Reservations WHERE rid = ? AND username = ? AND cancelled = 0";

  public Query(Connection conn) throws SQLException {
    super(conn);
    prepareStatements();
    this.logIn = false;
    itinerarys = new HashMap<>();
  }

  public Query() throws SQLException, IOException {
    this(openConnectionFromDbConn());
    this.logIn = false;
    itinerarys = new HashMap<>();
  }

  /**
   * Clear the data in any custom tables created.
   * <p>
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      clearTablesStatement.executeUpdate();
      clearTablesStatement.close();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  /*
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    clearTablesStatement = conn.prepareStatement(CLEAR_TABLES);
    checkUsernameIsLegalStatement = conn.prepareStatement(CHECK_USERNAME);
    getSaltAndHashStatement = conn.prepareStatement(GET_SALT_AND_HASH);
    createAccountStatement = conn.prepareStatement(CREATE_ACCOUNT);
    getDirectFlightsStatement = conn.prepareStatement(GET_DIRECT_FLIGHTS,
            ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    getIndirectFlightsStatement = conn.prepareStatement(GET_INDIRECT_FLIGHTS,
            ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    rOnSameDayStatement = conn.prepareStatement(RESERVATIONS_ON_SAME_DAY);
    checkCapacityExistStatement = conn.prepareStatement(CAPACITY_EXISTS);
    updateCapacityStatement = conn.prepareStatement(UPDATE_CAPACITY);
    addNewCapacityStatement = conn.prepareStatement(ADD_NEW_CAPACITY);
    getNumBookedSeatsStatement = conn.prepareStatement(GET_NUM_BOOKED_SEATS);
    addIDStatement = conn.prepareStatement(ADD_ID);
    addReservationStatement = conn.prepareStatement(ADD_RESERVATION);
    updateID = conn.prepareStatement(UPDATE_ID);
    getIDStatement = conn.prepareStatement(GET_ID);
    countIDStatement = conn.prepareStatement(COUNT_ID);
    checkUnpaidReservationStatement = conn.prepareStatement(CHECK_UNPAID_RESERVATION);
    getBalanceStatement = conn.prepareStatement(GET_BALANCE);
    getReservationPriceStatement = conn.prepareStatement(GET_RESERVATION_PRICE);
    payForReservationStatement = conn.prepareStatement(PAY_FOR_RESERVATION);
    updateBalanceStatement = conn.prepareStatement(UPDATE_BALANCE);
    checkHasReservationStatement = conn.prepareStatement(CHECK_HAS_RESERVATION);
    getReservationsStatement = conn.prepareStatement(GET_RESERVATIONS);
    checkPaidReservationStatement = conn.prepareStatement(CHECK_PAID_RESERVATION);
    cancelReservationStatement = conn.prepareStatement(CANCEL_RESERVATION);
    getCancelledFlightsStatement = conn.prepareStatement(GET_CANCELLED_FLIGHTS);
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   * @return If someone has already logged in, then return "User already logged in\n" For all other
   * errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    try {
      if (logIn) {
        return "User already logged in\n";
      } else {
        itinerarys = new HashMap<>();
        boolean legal = false;
        checkUsernameIsLegalStatement.setString(1, username.toLowerCase());
        ResultSet result = checkUsernameIsLegalStatement.executeQuery();
        result.next();
        if (result.getInt(1) == 1) {
          legal = true;
        }
        result.close();
        if (legal) {
          getSaltAndHashStatement.setString(1, username.toLowerCase());
          ResultSet hashAndSalt = getSaltAndHashStatement.executeQuery();
          hashAndSalt.next();
          byte[] salt = hashAndSalt.getBytes(2);
          byte[] hash = generateHash(password, salt);
          byte[] pwd = hashAndSalt.getBytes(1);
          hashAndSalt.close();
          if (Arrays.equals(hash, pwd)) {
            logIn = true;
            this.username = username.toLowerCase();
            return String.format("Logged in as %s\n", username);
          } else {
            return "Login failed\n";
          }
        }
      }
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return "Login failed\n";
  }

  private byte[] generateHash(String password, byte[] salt) {
    // Specify the hash parameters
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

    // Generate the hash
    SecretKeyFactory factory;
    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      return factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new IllegalStateException();
    }
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
   *                   otherwise).
   * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    for (int i = 0; i < 5; i++) {
      try {
        conn.setAutoCommit(false);
        checkUsernameIsLegalStatement.setString(1, username.toLowerCase());
        ResultSet result = checkUsernameIsLegalStatement.executeQuery();
        result.next();
        if (initAmount >= 0 && result.getInt(1) == 0) {
          byte[] salt = generateSalt();
          byte[] newPWD = generateHash(password, salt);
          createAccountStatement.setString(1, username.toLowerCase());
          createAccountStatement.setBytes(2, newPWD);
          createAccountStatement.setInt(3, initAmount);
          createAccountStatement.setBytes(4, salt);
          createAccountStatement.executeUpdate();
          result.close();
          conn.commit();
          conn.setAutoCommit(true);
          return String.format("Created user %s\n", username);
        } else {
          result.close();
          conn.setAutoCommit(true);
          return "Failed to create user\n";
        }
      } catch (SQLException e) {
        try {
          if (isDeadLock(e)) {
            conn.rollback();
          }
          conn.setAutoCommit(true);
        } catch (SQLException ex) {
          ex.printStackTrace();
        }
      }
    }
    return "Failed to create user\n";
  }

  private byte[] generateSalt() {
    // Generate a random cryptographic salt
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    return salt;
  }

  /**
   * Implement the search function.
   * <p>
   * Searches for flights from the given origin city to the given destination city, on the given day
   * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
   * is searches for direct flights and flights with two "hops." Only searches for up to the number
   * of itineraries given by {@code numberOfItineraries}.
   * <p>
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights, otherwise include
   *                            indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   * @return If no itineraries were found, return "No flights match your selection\n". If an error
   * occurs, then return "Failed to search\n".
   * <p>
   * Otherwise, the sorted itineraries printed in the following format:
   * <p>
   * Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
   * minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
   * <p>
   * Each flight should be printed using the same format as in the {@code Flight} class.
   * Itinerary numbers in each search should always start from 0 and increase by 1.
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight,
                                   int dayOfMonth, int numberOfItineraries) {
    StringBuffer sb = new StringBuffer();
    try {
      itinerarys = new HashMap<>();
      int count = 0;
      getDirectFlightsStatement.setInt(1, numberOfItineraries);
      getDirectFlightsStatement.setString(2, originCity);
      getDirectFlightsStatement.setString(3, destinationCity);
      getDirectFlightsStatement.setInt(4, dayOfMonth);
      ResultSet directResult = getDirectFlightsStatement.executeQuery();
      int numberOfDirectResult = getResultSize(directResult);
      if (numberOfDirectResult >= numberOfItineraries) {
        while (count < numberOfItineraries && directResult.next()) {
          sb.append(stringOfDirectFlight(directResult, count));
          count++;
        }
      } else if (directFlight) {
        while (count < numberOfDirectResult && directResult.next()) {
          sb.append(stringOfDirectFlight(directResult, count));
          count++;
        }
      } else {
        int maxIndirect = numberOfItineraries - numberOfDirectResult;
        getIndirectFlightsStatement.setInt(1, maxIndirect);
        getIndirectFlightsStatement.setString(2, originCity);
        getIndirectFlightsStatement.setString(3, destinationCity);
        getIndirectFlightsStatement.setInt(4, dayOfMonth);
        ResultSet indirectResult = getIndirectFlightsStatement.executeQuery();
        int indirectCount = 0;
        while (count < numberOfItineraries && (hasNext(directResult) || hasNext(indirectResult))) {
          if (!directIsChosen(directResult, indirectResult) && indirectCount < maxIndirect) {
            indirectResult.next();
            sb.append(stringOfIndirectResult(indirectResult, count));
            indirectCount++;
          } else {
            directResult.next();
            sb.append(stringOfDirectFlight(directResult, count));
          }
          count++;
        }
        indirectResult.close();
      }
      directResult.close();

      if (count == 0) {
        return "No flights match your selection\n";
      }
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return sb.toString();
  }

  // returns the size of the Result Set
  private int getResultSize(ResultSet result) {
    try {
      int size = 0;
      if (result != null) {
        result.beforeFirst();
        result.last();
        size = result.getRow();
        result.beforeFirst();
      }
      return size;
    } catch (SQLException e) {
      e.printStackTrace();
      return -1;
    }
  }

  private boolean hasNext(ResultSet result) {
    boolean has = false;
    try {
      boolean hasNext = result.next();
      if (hasNext) {
        has = true;
        result.previous();
      }
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return has;
  }

  private String stringOfDirectFlight(ResultSet result, int count) {
    String str = "";
    try {
      int time = result.getInt("actual_time");
      str += "Itinerary " + count + ": " + "1 flight(s), " + time + " minutes\n";
      int fid = result.getInt("fid");
      int dayOfMonth = result.getInt("day_of_month");
      String carrierId = result.getString("carrier_id");
      String flightNum = result.getString("flight_num");
      String originCity = result.getString("origin_city");
      String destCity = result.getString("dest_city");
      int capacity = result.getInt("capacity");
      int price = result.getInt("price");
      Flight f = new Flight(fid, dayOfMonth, carrierId, flightNum, originCity, destCity, time, capacity, price);
      str += f.toString() + "\n";
      List<Flight> flightList = new ArrayList<>();
      flightList.add(f);
      itinerarys.put(count, flightList);
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return str;
  }

  private String stringOfIndirectResult(ResultSet indirect, int ItineraryCount) {
    String result = "";
    try {
      int totalDuration = indirect.getInt("actual_time");
      result += "Itinerary " + ItineraryCount + ": 2 flight(s), " + totalDuration + " minutes\n";
      int f1_fid = indirect.getInt("f1_fid");
      int f1_dayOfMonth = indirect.getInt("f1_day_of_month");
      String f1_carrierId = indirect.getString("f1_carrier_id");
      String f1_flightNum = indirect.getString("f1_flight_num");
      String f1_originCity = indirect.getString("f1_origin_city");
      String f1_destCity = indirect.getString("f1_dest_city");
      int f1_time = indirect.getInt("f1_actual_time");
      int f1_capacity = indirect.getInt("f1_capacity");
      int f1_price = indirect.getInt("f1_price");
      Flight f1 = new Flight(f1_fid, f1_dayOfMonth, f1_carrierId, f1_flightNum, f1_originCity, f1_destCity, f1_time,
              f1_capacity, f1_price);
      result += f1.toString() + "\n";

      int f2_fid = indirect.getInt("f2_fid");
      int f2_dayOfMonth = indirect.getInt("f2_day_of_month");
      String f2_carrierId = indirect.getString("f2_carrier_id");
      String f2_flightNum = indirect.getString("f2_flight_num");
      String f2_originCity = indirect.getString("f2_origin_city");
      String f2_destCity = indirect.getString("f2_dest_city");
      int f2_time = indirect.getInt("f2_actual_time");
      int f2_capacity = indirect.getInt("f2_capacity");
      int f2_price = indirect.getInt("f2_price");
      Flight f2 = new Flight(f2_fid, f2_dayOfMonth, f2_carrierId, f2_flightNum, f2_originCity, f2_destCity,
              f2_time, f2_capacity, f2_price);
      result += f2.toString() + "\n";
      ArrayList<Flight> flightsList = new ArrayList<>();
      flightsList.add(f1);
      flightsList.add(f2);
      itinerarys.put(ItineraryCount, flightsList);
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return result;
  }

  private boolean directIsChosen(ResultSet directResult, ResultSet indirectResult) {
    try {
      boolean result;
      if (!directResult.next()) {
        result = false;
      } else if (!indirectResult.next()) {
        result = true;
      } else {
        int direct_time = directResult.getInt("actual_time");
        int indirect_time = indirectResult.getInt("actual_time");
        if (direct_time < indirect_time) {
          result = true;
        } else if (direct_time > indirect_time) {
          result = false;
        } else {
          int direct_fid = directResult.getInt("fid");
          int indirect_fid = indirectResult.getInt("f1_fid");
          if (direct_fid < indirect_fid) {
            result = true;
          } else if (direct_fid > indirect_fid) {
            result = false;
          } else {
            indirect_fid = indirectResult.getInt("f2_fid");
            result = direct_fid < indirect_fid;
          }
        }
      }
      directResult.previous();
      indirectResult.previous();
      return result;
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return true;
  }

  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
   *                    the current session.
   * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
   * If the user is trying to book an itinerary with an invalid ID or without having done a
   * search, then return "No such itinerary {@code itineraryId}\n". If the user already has
   * a reservation on the same day as the one that they are trying to book now, then return
   * "You cannot book two flights in the same day\n". For all other errors, return "Booking
   * failed\n".
   * <p>
   * And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
   * where reservationId is a unique number in the reservation system that starts from 1 and
   * increments by 1 each time a successful reservation is made by any user in the system.
   */
  public String transaction_book(int itineraryId) {
    for (int j = 0; j < 5; j++) {
      try {
        if (!logIn) {
          return "Cannot book reservations, not logged in\n";
        } else if (itinerarys.isEmpty() || !itinerarys.containsKey(itineraryId)) {
          return String.format("No such itinerary %d\n", itineraryId);
        } else if (hasOneBook(itineraryId)) {
          return "You cannot book two flights in the same day\n";
        }
        conn.setAutoCommit(false);
        List<Flight> itinerarysList = itinerarys.get(itineraryId);
        for (Flight i : itinerarysList) {
          if (checkInCapacity(i.fid)) {
            updateCapacityStatement.setInt(1, 1);
            updateCapacityStatement.setInt(2, i.fid);
            updateCapacityStatement.executeUpdate();
          } else {
            addNewCapacityStatement.setInt(1, i.fid);
            addNewCapacityStatement.executeUpdate();
          }
          if (i.capacity < numOfBookedSeats(i.fid)) {
            conn.rollback();
            conn.setAutoCommit(true);
            return "Booking failed\n";
          }
        }
        if (IDTableIsEmpty()) {
          addIDStatement.executeUpdate();
        } else {
          updateID.executeUpdate();
        }
        ResultSet result = getIDStatement.executeQuery();
        result.next();
        int rid = result.getInt(1);
        int direct = itinerarysList.size() % 2;
        for (Flight i : itinerarysList) {
          addReservation(i, rid, direct);
        }
        conn.commit();
        conn.setAutoCommit(true);
        return String.format("Booked flight(s), reservation ID: %d\n", rid);
      } catch (SQLException e) {
        e.printStackTrace();
        try {
          if (isDeadLock(e)) {
            conn.rollback();
          }
          conn.setAutoCommit(true);
        } catch (SQLException se) {
          se.printStackTrace();
        }
      }
    }
    return "Booking failed\n";
  }

  private boolean hasOneBook(int itineraryId) {
    try {
      int date = itinerarys.get(itineraryId).get(0).dayOfMonth;
      rOnSameDayStatement.setInt(1, date);
      rOnSameDayStatement.setString(2, username);
      ResultSet result = rOnSameDayStatement.executeQuery();
      result.next();
      return result.getInt(1) > 0;
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }

  private boolean checkInCapacity(int fid) {
    try {
      checkCapacityExistStatement.setInt(1, fid);
      ResultSet result = checkCapacityExistStatement.executeQuery();
      result.next();
      return result.getInt(1) == 1;
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }

  private int numOfBookedSeats(int fid) {
    try {
      getNumBookedSeatsStatement.setInt(1, fid);
      ResultSet result = getNumBookedSeatsStatement.executeQuery();
      result.next();
      return result.getInt(1);
    } catch (SQLException e) {
      e.printStackTrace();
      return -1;
    }
  }

  private void addReservation(Flight i, int Rid, int direct) {
    try {
      conn.setAutoCommit(false);
      // insert one row in Reservations table
      addReservationStatement.setInt(1, Rid);
      addReservationStatement.setString(2, username);
      addReservationStatement.setInt(3, direct);
      addReservationStatement.setInt(4, i.fid);
      addReservationStatement.setInt(5, i.dayOfMonth);
      addReservationStatement.setString(6, i.carrierId);
      addReservationStatement.setString(7, i.flightNum);
      addReservationStatement.setString(8, i.originCity);
      addReservationStatement.setString(9, i.destCity);
      addReservationStatement.setInt(10, i.time);
      addReservationStatement.setInt(11, i.price);
      addReservationStatement.setInt(12, i.capacity);
      addReservationStatement.setInt(13, 0);
      addReservationStatement.setInt(14, 0);
      addReservationStatement.executeUpdate();
      conn.commit();
      conn.setAutoCommit(true);
    } catch (SQLException e) {
      e.printStackTrace();
      try {
        if (isDeadLock(e)) {
          conn.rollback();
        }
        conn.setAutoCommit(true);
      } catch (SQLException se) {
        se.printStackTrace();
      }
    }
  }

  private boolean IDTableIsEmpty() {
    try {
      ResultSet result = countIDStatement.executeQuery();
      result.next();
      return result.getInt(1) == 0;
    } catch (SQLException e) {
      e.printStackTrace();
      return true;
    }
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
   * is not found / not under the logged in user's name, then return "Cannot find unpaid
   * reservation [reservationId] under user: [username]\n" If the user does not have enough
   * money in their account, then return "User has only [balance] in account but itinerary
   * costs [cost]\n" For all other errors, return "Failed to pay for reservation
   * [reservationId]\n"
   * <p>
   * If successful, return "Paid reservation: [reservationId] remaining balance:
   * [balance]\n" where [balance] is the remaining balance in the user's account.
   */
  public String transaction_pay(int reservationId) {
    for (int i = 0; i < 5; i++) {
      try {
        if (!logIn) {
          return "Cannot pay, not logged in\n";
        }
        if (!unpaidReservationExists(reservationId)) {
          return "Cannot find unpaid reservation " + reservationId + " under user: " + username + "\n";
        }
        int balance = getBalance();
        int price = getPrice(reservationId);
        if (balance < price) {
          return "User has only " + balance + " in account but itinerary costs " + price + "\n";
        }
        conn.setAutoCommit(false);
        payForReservationStatement.setInt(1, reservationId);
        payForReservationStatement.executeUpdate();

        updateBalanceStatement.setInt(1, -1 * price);
        updateBalanceStatement.setString(2, this.username);
        updateBalanceStatement.executeUpdate();

        conn.commit();
        conn.setAutoCommit(true);
        return "Paid reservation: " + reservationId + " remaining balance: " + (balance - price) + "\n";
      } catch (SQLException e) {
        e.printStackTrace();
        try {
          if (isDeadLock(e)) {
            conn.rollback();
          }
          conn.setAutoCommit(true);
        } catch (SQLException se) {
          se.printStackTrace();
        }
      }
    }
    return "Failed to pay for reservation " + reservationId + "\n";
  }

  private boolean unpaidReservationExists(int reservationId) {
    try {
      checkUnpaidReservationStatement.setInt(1, reservationId);
      checkUnpaidReservationStatement.setString(2, this.username);
      ResultSet result = checkUnpaidReservationStatement.executeQuery();
      return result.next();
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }

  private int getBalance() {
    try {
      getBalanceStatement.setString(1, this.username);
      ResultSet res = getBalanceStatement.executeQuery();
      res.next();
      return res.getInt(1);
    } catch (SQLException e) {
      e.printStackTrace();
      return -1;
    }
  }

  private int getPrice(int rid) {
    try {
      getReservationPriceStatement.setInt(1, rid);
      getReservationPriceStatement.setString(2, this.username);
      ResultSet result = getReservationPriceStatement.executeQuery();
      int price = 0;
      while (result.next()) {
        price += result.getInt(1);
      }
      return price;
    } catch (SQLException e) {
      e.printStackTrace();
      return -1;
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
   * the user has no reservations, then return "No reservations found\n" For all other
   * errors, return "Failed to retrieve reservations\n"
   * <p>
   * Otherwise return the reservations in the following format:
   * <p>
   * Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
   * reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
   * [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
   * reservation]\n ...
   * <p>
   * Each flight should be printed using the same format as in the {@code Flight} class.
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    for (int i = 0; i < 5; i++) {
      try {
        if (!logIn) {
          return "Cannot view reservations, not logged in\n";
        } else if (!hasReservation()) {
          return "No reservations found\n";
        }
        conn.setAutoCommit(false);
        StringBuffer buffer = new StringBuffer();
        getReservationsStatement.setString(1, this.username);
        ResultSet result = getReservationsStatement.executeQuery();
        while (result.next()) {
          int rid = result.getInt("rid");
          int paid = result.getInt("paid");
          int direct = result.getInt("direct");
          buffer.append("Reservation " + rid + " paid: " + (paid == 1) + ":\n");
          if (direct == 1) {
            appendBuffer(buffer, result);
          } else if (direct == 0) {
            appendBuffer(buffer, result);
            result.next();
            appendBuffer(buffer, result);
          }
        }
        conn.commit();
        conn.setAutoCommit(true);
        return buffer.toString();
      } catch (SQLException e) {
        e.printStackTrace();
        try {
          if (isDeadLock(e)) {
            conn.rollback();
          }
          conn.setAutoCommit(true);
        } catch (SQLException se) {
          se.printStackTrace();
        }
      }
    }
    return "Failed to retrieve reservations\n";
  }

  private boolean hasReservation() {
    try {
      checkHasReservationStatement.setString(1, username);
      ResultSet result = checkHasReservationStatement.executeQuery();
      result.next();
      return result.getInt(1) > 0;
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }

  private void appendBuffer(StringBuffer buffer, ResultSet result) {
    try {
      int fid = result.getInt("fid");
      int dayOfMonth = result.getInt("day");
      String carrier_id = result.getString("carrier_id");
      String flight_num = result.getString("flight_num");
      String origin_city = result.getString("origin_city");
      String dest_city = result.getString("dest_city");
      int actual_time = result.getInt("actual_time");
      int capacity = result.getInt("capacity");
      int price = result.getInt("price");
      Flight f = new Flight(fid, dayOfMonth, carrier_id, flight_num, origin_city, dest_city, actual_time,
              capacity, price);
      buffer.append(f.toString() + "\n");
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
   * all other errors, return "Failed to cancel reservation [reservationId]\n"
   * <p>
   * If successful, return "Canceled reservation [reservationId]\n"
   * <p>
   * Even though a reservation has been canceled, its ID should not be reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    for (int j = 0; j < 5; j++) {
      try {
        if (!logIn) {
          return "Cannot cancel reservations, not logged in\n";
        }
        if (!(unpaidReservationExists(reservationId) || paidReservationExists(reservationId))) {
          return "Failed to cancel reservation " + reservationId + "\n";
        } else {
          conn.setAutoCommit(false);
          if (paidReservationExists(reservationId)) {
            int cost = getPrice(reservationId);
            updateBalanceStatement.setInt(1, cost);
            updateBalanceStatement.setString(2, this.username);
            updateBalanceStatement.executeUpdate();
          }
          cancelReservationStatement.setInt(1, reservationId);
          cancelReservationStatement.executeUpdate();

          getCancelledFlightsStatement.setInt(1, reservationId);
          getCancelledFlightsStatement.setString(2, username);
          ResultSet result = getCancelledFlightsStatement.executeQuery();
          while (result.next()) {
            int fid = result.getInt("fid");
            updateCapacityStatement.setInt(1, -1);
            updateCapacityStatement.setInt(2, fid);
            updateCapacityStatement.executeUpdate();
          }
          conn.commit();
          conn.setAutoCommit(true);
          return "Canceled reservation " + reservationId + "\n";
        }
      } catch (SQLException e) {
        e.printStackTrace();
        try {
          if (isDeadLock(e)) {
            conn.rollback();
          }
          conn.setAutoCommit(true);
        } catch (SQLException se) {
          se.printStackTrace();
        }
      }
    }
    return "Failed to cancel reservation " + reservationId + "\n";
  }

  private boolean paidReservationExists(int reservationId) {
    try {
      checkPaidReservationStatement.setInt(1, reservationId);
      checkPaidReservationStatement.setString(2, this.username);
      ResultSet result = checkPaidReservationStatement.executeQuery();
      return result.next();
    } catch (SQLException e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }

  public static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;

    public Flight(int fid, int dayOfMonth, String carrierId, String flightNum, String originCity, String destCity, int time, int capacity, int price) {
      this.fid = fid;
      this.dayOfMonth = dayOfMonth;
      this.carrierId = carrierId;
      this.flightNum = flightNum;
      this.originCity = originCity;
      this.destCity = destCity;
      this.time = time;
      this.capacity = capacity;
      this.price = price;
    }

    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
          + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
          + " Capacity: " + capacity + " Price: " + price;
    }
  }
}
