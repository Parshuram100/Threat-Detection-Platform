import sqlite3
import pandas as pd
from tabulate import tabulate

def explore_database():
    try:
        # Connect to the database
        conn = sqlite3.connect('db.sqlite3')
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        print("\nAvailable Tables:")
        print("-" * 50)
        for i, table in enumerate(tables, 1):
            print(f"{i}. {table[0]}")

        while True:
            try:
                choice = int(input("\nEnter table number to explore (0 to exit): "))
                if choice == 0:
                    break
                
                if 1 <= choice <= len(tables):
                    table_name = tables[choice-1][0]
                    
                    # Get table structure
                    cursor.execute(f"PRAGMA table_info({table_name});")
                    columns = cursor.fetchall()
                    
                    print(f"\nStructure of {table_name}:")
                    print("-" * 50)
                    print(tabulate(columns, headers=['cid', 'name', 'type', 'notnull', 'dflt_value', 'pk'], tablefmt='grid'))
                    
                    # Get sample data
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
                    data = cursor.fetchall()
                    
                    if data:
                        print(f"\nSample data from {table_name}:")
                        print("-" * 50)
                        df = pd.DataFrame(data, columns=[col[1] for col in columns])
                        print(tabulate(df, headers='keys', tablefmt='grid', showindex=False))
                    else:
                        print("No data found in this table.")
                
                else:
                    print("Invalid choice. Please try again.")
            
            except ValueError:
                print("Please enter a valid number.")
            except Exception as e:
                print(f"An error occurred: {str(e)}")

    except sqlite3.Error as e:
        print(f"Database error: {str(e)}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    explore_database() 