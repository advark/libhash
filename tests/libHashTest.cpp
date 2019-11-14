/*
 * Copyright (C) 2017-19 Yanick Poirier <ypoirier at hotmail.com>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

/*
 * File:   libHashTest.cpp
 * Author: Yanick Poirier <ypoirier at hotmail.com>
 *
 * Created on 2019-11-01, 21:05:16
 */

// CppUnit site http://sourceforge.net/projects/cppunit/files

#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestRunner.h>

#include <cppunit/Test.h>
#include <cppunit/TestFailure.h>
#include <cppunit/portability/Stream.h>

class ProgressListener : public CPPUNIT_NS::TestListener {
public:

    ProgressListener( )
            : m_lastTestFailed( false ) { }

    ~ProgressListener( ) { }

    void startTest( CPPUNIT_NS::Test *test ) {
        CPPUNIT_NS::stdCOut( ) << test->getName( );
        CPPUNIT_NS::stdCOut( ) << "\n";
        CPPUNIT_NS::stdCOut( ).flush( );

        m_lastTestFailed = false;
    }

    void addFailure( const CPPUNIT_NS::TestFailure &failure ) {
        CPPUNIT_NS::stdCOut( ) << ( failure.isError( ) ? "error" : "Failed" );
        m_lastTestFailed = true;
    }

    void endTest( CPPUNIT_NS::Test *test ) {
        if ( !m_lastTestFailed )
            CPPUNIT_NS::stdCOut( ) << " : OK";
        CPPUNIT_NS::stdCOut( ) << "\n";
    }

private:
    /// Prevents the use of the copy constructor.
    ProgressListener( const ProgressListener &copy );

    /// Prevents the use of the copy operator.
    void operator=(const ProgressListener &copy );

private:
    bool m_lastTestFailed;
} ;

int main( ) {
    // Create the event manager and test controller
    CPPUNIT_NS::TestResult controller;

    // Add a listener that colllects test result
    CPPUNIT_NS::TestResultCollector result;
    controller.addListener( &result );

    // Add a listener that print dots as test run.
    ProgressListener progress;
    controller.addListener( &progress );

    // Add the top suite to the test runner
    CPPUNIT_NS::TestRunner runner;
    runner.addTest( CPPUNIT_NS::TestFactoryRegistry::getRegistry( ).makeTest( ) );
    runner.run( controller );

    // Print test in a compiler compatible format.
    CPPUNIT_NS::CompilerOutputter outputter( &result, CPPUNIT_NS::stdCOut( ) );
    outputter.write( );

    return result.wasSuccessful( ) ? 0 : 1;
}
